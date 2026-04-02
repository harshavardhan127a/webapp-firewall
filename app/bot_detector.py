"""
Enhanced Behavioral Bot Detection Module v2.0
=============================================
Improvements over v1.0:
- Session fingerprinting (header ordering consistency)
- Endpoint access pattern analysis (sequential enumeration detection)
- Slow-attack detection (credential stuffing, admin probing)
- Login attempt tracking per IP with time-windowed counters
- Output compatible with DecisionEngine signals

Detection signals:
  1. Missing standard browser headers (Accept-Language, Accept-Encoding, Accept)
  2. Robotic request timing (suspiciously regular intervals)
  3. Path scanning behavior (high unique-path-to-request ratio)
  4. Lack of cookie/session state maintenance
  5. Missing Referer on subsequent requests
  6. HTTP method enumeration (using many different methods)
  7. Session fingerprint inconsistency (header set changes)
  8. Sequential endpoint enumeration (/user/1, /user/2, ...)
  9. Slow credential stuffing (login attempts over long windows)
  10. Admin/sensitive endpoint probing
"""
import re
import time
from typing import Dict, Tuple, List, Set, Optional
from collections import defaultdict


# Sensitive endpoints for slow-attack tracking
SENSITIVE_ENDPOINTS = {
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/admin", "/administrator", "/wp-admin", "/wp-login",
    "/api/login", "/api/auth", "/api/token",
    "/register", "/signup", "/sign-up",
    "/forgot-password", "/reset-password",
    "/api/users", "/api/accounts",
}

# Sequential path pattern (e.g., /user/123 → /user/124)
NUMERIC_PATH_SEGMENT = re.compile(r'/(\d+)(?:/|$)')


class BehavioralBotDetector:
    """
    Detect automated tools through behavioral analysis.

    Tracks per-IP session data across requests and computes a
    bot probability score (0-100). Higher scores indicate bot-like behavior.
    """

    def __init__(self):
        self._session_data: Dict[str, dict] = {}

    def _get_session(self, ip: str) -> dict:
        """Get or create session data for an IP"""
        if ip not in self._session_data:
            self._session_data[ip] = {
                'first_seen': time.time(),
                'request_count': 0,
                'paths_visited': set(),
                'methods_used': set(),
                'avg_interval': 0,
                'last_request': 0,
                'intervals': [],
                'has_cookies': False,
                'has_referer': False,
                'score': 0,
                'indicators': [],
                # v2.0 additions
                'header_fingerprints': [],
                'numeric_path_ids': [],
                'sensitive_hits': [],
                'login_attempts': [],
                'user_agents_seen': set(),
            }
        return self._session_data[ip]

    def _compute_header_fingerprint(self, headers: dict) -> str:
        """
        Compute a fingerprint based on which headers are present and their order.
        Real browsers have consistent header sets; bots often vary.
        """
        # Use a sorted set of header names (case-normalized)
        header_names = sorted(k.lower() for k in headers.keys())
        # Filter to standard browser headers for fingerprinting
        relevant = [
            h for h in header_names
            if h in {
                'accept', 'accept-language', 'accept-encoding',
                'cache-control', 'connection', 'dnt', 'upgrade-insecure-requests',
                'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site',
                'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
            }
        ]
        return "|".join(relevant)

    def _detect_sequential_enumeration(self, session: dict, path: str) -> bool:
        """
        Detect sequential endpoint enumeration like /user/1, /user/2, /user/3.
        """
        match = NUMERIC_PATH_SEGMENT.search(path)
        if not match:
            return False

        numeric_id = int(match.group(1))
        base_path = path[:match.start(1)]

        session['numeric_path_ids'].append((base_path, numeric_id, time.time()))
        # Keep last 50 entries
        session['numeric_path_ids'] = session['numeric_path_ids'][-50:]

        # Check for sequential pattern in same base path
        recent_ids = [
            nid for bp, nid, ts in session['numeric_path_ids']
            if bp == base_path and time.time() - ts < 120  # 2 minute window
        ]

        if len(recent_ids) >= 5:
            # Check if they form a sequential run
            sorted_ids = sorted(recent_ids)
            sequential_count = sum(
                1 for i in range(1, len(sorted_ids))
                if sorted_ids[i] - sorted_ids[i - 1] <= 2  # allow small gaps
            )
            return sequential_count >= 4

        return False

    def _check_slow_attack(self, session: dict, path: str) -> bool:
        """
        Detect slow credential stuffing or admin probing.
        Track hits to sensitive endpoints over long windows.
        """
        # Normalize path
        normalized = path.rstrip('/').lower()

        # Check if it's a sensitive endpoint
        is_sensitive = any(
            normalized == ep or normalized.startswith(ep + '/')
            for ep in SENSITIVE_ENDPOINTS
        )

        if is_sensitive:
            now = time.time()
            session['sensitive_hits'].append(now)
            # Keep last 100 entries
            session['sensitive_hits'] = session['sensitive_hits'][-100:]

            # Check for slow but persistent probing
            # More than 10 sensitive endpoint hits in 10 minutes
            window = 600  # 10 minutes
            recent = [t for t in session['sensitive_hits'] if now - t < window]
            return len(recent) >= 10

        return False

    def _track_login_attempts(self, session: dict, path: str, method: str) -> int:
        """
        Track login attempts. Returns count in the last 15 minutes.
        """
        login_paths = {'/login', '/signin', '/sign-in', '/auth',
                       '/api/login', '/api/auth', '/api/token'}
        normalized = path.rstrip('/').lower()

        if method == 'POST' and normalized in login_paths:
            now = time.time()
            session['login_attempts'].append(now)
            session['login_attempts'] = session['login_attempts'][-200:]

            window = 900  # 15 minutes
            return sum(1 for t in session['login_attempts'] if now - t < window)

        return 0

    def analyze(self, ip: str, request_data: dict) -> Tuple[float, List[str]]:
        """
        Analyze a request for bot-like behavior patterns.

        Args:
            ip: Client IP address
            request_data: Dict with 'headers', 'path', 'method' keys

        Returns:
            (bot_score 0-100, list of indicator names)
        """
        session = self._get_session(ip)
        headers = request_data.get('headers', {})
        path = request_data.get('path', '/')
        method = request_data.get('method', 'GET')
        now = time.time()
        indicators = []

        # -------- Update session state --------
        session['request_count'] += 1
        session['paths_visited'].add(path)
        session['methods_used'].add(method)

        # Track user agents
        ua = headers.get('User-Agent', '') or headers.get('user-agent', '')
        if ua:
            session['user_agents_seen'].add(ua[:100])

        if session['last_request'] > 0:
            interval = now - session['last_request']
            session['intervals'].append(interval)
            session['intervals'] = session['intervals'][-50:]
        session['last_request'] = now

        score = 0.0

        # -------- Signal 1: Missing standard browser headers --------
        if not headers.get('Accept-Language') and not headers.get('accept-language'):
            score += 10
            indicators.append('missing_accept_language')

        if not headers.get('Accept-Encoding') and not headers.get('accept-encoding'):
            score += 5
            indicators.append('missing_accept_encoding')

        if not headers.get('Accept') and not headers.get('accept'):
            score += 10
            indicators.append('missing_accept')

        # -------- Signal 2: Robotic request timing --------
        if len(session['intervals']) >= 5:
            avg = sum(session['intervals']) / len(session['intervals'])
            if avg > 0:
                variance = sum(
                    (i - avg) ** 2 for i in session['intervals']
                ) / len(session['intervals'])
                coefficient_of_variation = (variance ** 0.5) / avg

                if coefficient_of_variation < 0.1 and avg < 2.0:
                    score += 30
                    indicators.append('robotic_timing')
                elif coefficient_of_variation < 0.15 and avg < 1.0:
                    score += 20
                    indicators.append('semi_robotic_timing')

        # -------- Signal 3: Path scanning --------
        if session['request_count'] > 10:
            path_diversity = len(session['paths_visited']) / session['request_count']
            if path_diversity > 0.9:
                score += 20
                indicators.append('path_scanning')
            elif path_diversity > 0.7:
                score += 10
                indicators.append('high_path_diversity')

        # -------- Signal 4: No cookie state --------
        if 'Cookie' in headers or 'cookie' in headers:
            session['has_cookies'] = True
        if not session['has_cookies'] and session['request_count'] > 5:
            score += 10
            indicators.append('no_cookie_state')

        # -------- Signal 5: No Referer on non-entry pages --------
        if headers.get('Referer') or headers.get('referer'):
            session['has_referer'] = True
        if not session['has_referer'] and session['request_count'] > 3:
            score += 5
            indicators.append('no_referer')

        # -------- Signal 6: HTTP method enumeration --------
        if len(session['methods_used']) > 4:
            score += 15
            indicators.append('method_enumeration')
        elif len(session['methods_used']) > 3:
            score += 5
            indicators.append('unusual_method_variety')

        # -------- Signal 7: Header fingerprint inconsistency (v2.0) --------
        fingerprint = self._compute_header_fingerprint(headers)
        session['header_fingerprints'].append(fingerprint)
        session['header_fingerprints'] = session['header_fingerprints'][-20:]

        if len(session['header_fingerprints']) >= 5:
            unique_fingerprints = set(session['header_fingerprints'])
            if len(unique_fingerprints) > 3:
                score += 15
                indicators.append('header_fingerprint_inconsistency')

        # -------- Signal 8: Sequential enumeration (v2.0) --------
        if self._detect_sequential_enumeration(session, path):
            score += 25
            indicators.append('sequential_enumeration')

        # -------- Signal 9: Slow credential stuffing (v2.0) --------
        login_count = self._track_login_attempts(session, path, method)
        if login_count >= 20:
            score += 30
            indicators.append('credential_stuffing')
        elif login_count >= 10:
            score += 15
            indicators.append('suspicious_login_volume')

        # -------- Signal 10: Sensitive endpoint probing (v2.0) --------
        if self._check_slow_attack(session, path):
            score += 20
            indicators.append('sensitive_endpoint_probing')

        # -------- Signal 11: Multiple user-agents (v2.0) --------
        if len(session['user_agents_seen']) > 3:
            score += 10
            indicators.append('multiple_user_agents')

        # Cap at 100
        session['score'] = min(score, 100)
        session['indicators'] = indicators

        return session['score'], indicators

    def get_session_info(self, ip: str) -> dict:
        """Get current session data for an IP"""
        if ip not in self._session_data:
            return {}
        session = self._session_data[ip]
        return {
            'request_count': session['request_count'],
            'paths_visited': len(session['paths_visited']),
            'methods_used': list(session['methods_used']),
            'score': session['score'],
            'indicators': session['indicators'],
            'first_seen': session['first_seen'],
            'login_attempts': len(session.get('login_attempts', [])),
            'user_agents': len(session.get('user_agents_seen', set())),
        }

    def cleanup(self, max_age_minutes: int = 30):
        """Remove stale session data"""
        cutoff = time.time() - (max_age_minutes * 60)
        expired = [
            ip for ip, data in self._session_data.items()
            if data['last_request'] < cutoff
        ]
        for ip in expired:
            del self._session_data[ip]
