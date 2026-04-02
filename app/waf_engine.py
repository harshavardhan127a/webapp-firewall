"""
Improved WAF Engine v3.0
Features:
- Context-aware analysis (different rules for path vs params vs body vs headers)
- Deep payload normalization via PayloadNormalizer
- Configurable protection module toggles via config
- Risk scoring integration via DetectionResult list
- Response inspection for data leakage (paranoia level 4)
- No legacy dead code
"""
import re
import json
import os
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass

# Import the deep normalizer (H1 fix)
from payload_normalizer import PayloadNormalizer


@dataclass
class DetectionResult:
    """Result of attack detection"""
    is_malicious: bool
    attack_type: Optional[str] = None
    pattern_matched: Optional[str] = None
    details: Optional[str] = None
    severity: str = "medium"  # low, medium, high, critical
    context: str = ""  # where the match was found: params, body, path, headers


class WAFEngine:
    """
    Web Application Firewall Engine v3
    - Context-aware rule application
    - Deep payload normalization
    - Configurable protection toggles
    """

    SEVERITY_MAP = {
        'sql_injection': 'critical',
        'xss': 'high',
        'command_injection': 'critical',
        'path_traversal': 'high',
        'xxe': 'critical',
        'ssrf': 'high',
        'lfi': 'high',
        'rfi': 'high',
        'ldap_injection': 'high',
        'header_injection': 'medium',
        'protocol_attacks': 'medium',
        'scanner_detection': 'low'
    }

    # H3 Fix: Context-specific rule mapping
    # Each context only checks the attack categories relevant to it
    CONTEXT_RULES = {
        'path': ['path_traversal', 'lfi', 'rfi', 'command_injection'],
        'params': ['sql_injection', 'xss', 'command_injection', 'ssrf',
                   'ldap_injection', 'path_traversal', 'lfi', 'rfi',
                   'header_injection', 'xxe'],
        'body': ['sql_injection', 'xss', 'xxe', 'command_injection',
                 'ssrf', 'ldap_injection', 'rfi', 'header_injection'],
        'headers': ['header_injection', 'ssrf', 'xss'],
        'user_agent': ['scanner_detection'],
    }

    # H7 Fix: Mapping from attack category to config toggle attribute
    PROTECTION_CONFIG_MAP = {
        'sql_injection': 'PROTECTION_SQL_INJECTION',
        'xss': 'PROTECTION_XSS',
        'path_traversal': 'PROTECTION_PATH_TRAVERSAL',
        'command_injection': 'PROTECTION_COMMAND_INJECTION',
        'xxe': 'PROTECTION_XXE',
        'ssrf': 'PROTECTION_SSRF',
        'lfi': 'PROTECTION_LFI',
        'rfi': 'PROTECTION_RFI',
    }

    def __init__(self, rules_path: str = None, paranoia_level: int = 2):
        """
        Initialize WAF Engine

        Args:
            rules_path: Path to rules JSON file
            paranoia_level: 1-4 (higher = more strict, more false positives)
        """
        self.paranoia_level = paranoia_level
        self.rules = self._load_rules(rules_path)
        self.compiled_patterns = self._compile_patterns()
        self._enabled_categories = self._load_enabled_categories()

    def _load_rules(self, rules_path: str = None) -> Dict:
        """Load rules from JSON file"""
        if rules_path is None:
            rules_path = os.path.join(os.path.dirname(__file__), 'rules.json')

        if not os.path.exists(rules_path):
            raise FileNotFoundError(f"Rules file not found: {rules_path}")

        with open(rules_path) as f:
            return json.load(f)

    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Pre-compile regex patterns for performance"""
        compiled = {}

        for category, data in self.rules.items():
            if isinstance(data, dict) and 'patterns' in data:
                if data.get('enabled', True):
                    compiled[category] = [
                        re.compile(pattern, re.IGNORECASE | re.DOTALL)
                        for pattern in data['patterns']
                    ]

        # Handle scanner detection separately (user agents)
        if 'scanner_detection' in self.rules:
            scanner_data = self.rules['scanner_detection']
            if scanner_data.get('enabled', True) and 'user_agents' in scanner_data:
                compiled['scanner_user_agents'] = [
                    re.compile(ua, re.IGNORECASE)
                    for ua in scanner_data['user_agents']
                ]

        return compiled

    def _load_enabled_categories(self) -> set:
        """H7 Fix: Load which protection categories are enabled from config"""
        try:
            import config
            enabled = set()
            for category in self.SEVERITY_MAP:
                config_attr = self.PROTECTION_CONFIG_MAP.get(category)
                if config_attr is None:
                    # Categories without a toggle are always enabled
                    enabled.add(category)
                elif getattr(config, config_attr, True):
                    enabled.add(category)
            return enabled
        except ImportError:
            # If config is unavailable, enable everything
            return set(self.SEVERITY_MAP.keys())

    def _check_patterns(
        self,
        content: str,
        category: str
    ) -> List[Tuple[str, str]]:
        """
        Check content against patterns in a category.
        Returns list of (pattern, matched_text) tuples for ALL matches.
        (Changed from returning first match to returning all matches for scoring)
        """
        if category not in self.compiled_patterns:
            return []

        matches = []
        for pattern in self.compiled_patterns[category]:
            match = pattern.search(content)
            if match:
                matches.append((pattern.pattern, match.group()[:100]))

        return matches

    def _check_scanner_user_agent(self, user_agent: str) -> Tuple[bool, Optional[str]]:
        """Check if user agent matches known scanner patterns"""
        if 'scanner_user_agents' not in self.compiled_patterns:
            return False, None

        for pattern in self.compiled_patterns['scanner_user_agents']:
            if pattern.search(user_agent):
                return True, pattern.pattern

        return False, None

    def check_request(self, request_data: Dict[str, Any]) -> DetectionResult:
        """
        Check a request for attacks with context-aware analysis.

        Uses PayloadNormalizer for deep decoding and applies rules
        only to contexts where they are relevant.

        Args:
            request_data: Dictionary containing:
                - headers: Dict of request headers
                - params: Dict of query parameters
                - body: Request body as string
                - path: Request path
                - method: HTTP method

        Returns:
            DetectionResult with detection details
        """
        headers = request_data.get('headers', {})
        params = request_data.get('params', {})
        body = request_data.get('body', '')
        path = request_data.get('path', '')
        method = request_data.get('method', 'GET')

        # ---- Scanner user agent check (fast path) ----
        user_agent = headers.get('User-Agent', '') or headers.get('user-agent', '')
        if 'scanner_detection' in self._enabled_categories:
            matched, pattern = self._check_scanner_user_agent(user_agent)
            if matched:
                return DetectionResult(
                    is_malicious=True,
                    attack_type='scanner_detection',
                    pattern_matched=pattern,
                    details=f"Known scanner user agent detected: {user_agent[:100]}",
                    severity='low',
                    context='user_agent'
                )

        # ---- Build context map (H3 Fix: context-aware) ----
        # Join param values individually instead of str(dict) which escapes
        # special characters and wraps in Python repr syntax
        params_content = ' '.join(str(v) for v in params.values()) if params else ''
        context_map = {
            'params': params_content,
            'body': body or '',
            'path': path or '',
        }

        # Add header values at higher paranoia levels
        if self.paranoia_level >= 2:
            header_values = []
            for key, value in headers.items():
                if key.lower() not in ('cookie', 'authorization', 'user-agent'):
                    header_values.append(str(value))
            context_map['headers'] = ' '.join(header_values)

        # ---- Check each context against its relevant categories ----
        for context_name, content in context_map.items():
            if not content:
                continue

            # Get categories relevant to this context
            applicable_categories = self.CONTEXT_RULES.get(
                context_name,
                list(self.SEVERITY_MAP.keys())  # fallback: check all
            )

            # Filter by enabled protections (H7 Fix)
            active_categories = [
                cat for cat in applicable_categories
                if cat in self._enabled_categories
            ]

            # H1 Fix: Use deep payload normalizer instead of basic decoding
            decoded_versions = PayloadNormalizer.normalize(content, max_depth=3)

            for category in active_categories:
                for decoded_content in decoded_versions:
                    matches = self._check_patterns(decoded_content, category)
                    if matches:
                        # Use first match for the detection result
                        pattern, matched_text = matches[0]
                        return DetectionResult(
                            is_malicious=True,
                            attack_type=category,
                            pattern_matched=pattern,
                            details=f"Malicious pattern detected in {context_name}",
                            severity=self.SEVERITY_MAP.get(category, 'medium'),
                            context=context_name
                        )

        # ---- Protocol attack check (HTTP method) ----
        if 'protocol_attacks' in self._enabled_categories:
            matches = self._check_patterns(method, 'protocol_attacks')
            if matches:
                pattern, matched_text = matches[0]
                return DetectionResult(
                    is_malicious=True,
                    attack_type='protocol_attacks',
                    pattern_matched=pattern,
                    details=f"Suspicious HTTP method: {method}",
                    severity='medium',
                    context='method'
                )

        return DetectionResult(is_malicious=False)

    def check_request_all_signals(self, request_data: Dict[str, Any]) -> List[DetectionResult]:
        """
        Check a request and return ALL detection signals (for risk scoring).

        Unlike check_request() which returns on first match, this method
        collects every signal across all contexts for the risk scorer.

        Returns:
            List of DetectionResult for each detected signal
        """
        headers = request_data.get('headers', {})
        params = request_data.get('params', {})
        body = request_data.get('body', '')
        path = request_data.get('path', '')
        method = request_data.get('method', 'GET')
        signals = []

        # Scanner check
        user_agent = headers.get('User-Agent', '') or headers.get('user-agent', '')
        if 'scanner_detection' in self._enabled_categories:
            matched, pattern = self._check_scanner_user_agent(user_agent)
            if matched:
                signals.append(DetectionResult(
                    is_malicious=True,
                    attack_type='scanner_detection',
                    pattern_matched=pattern,
                    details=f"Known scanner: {user_agent[:100]}",
                    severity='low',
                    context='user_agent'
                ))

        # Build context map — join param values individually
        params_content = ' '.join(str(v) for v in params.values()) if params else ''
        context_map = {
            'params': params_content,
            'body': body or '',
            'path': path or '',
        }
        if self.paranoia_level >= 2:
            header_values = []
            for key, value in headers.items():
                if key.lower() not in ('cookie', 'authorization', 'user-agent'):
                    header_values.append(str(value))
            context_map['headers'] = ' '.join(header_values)

        # Check all contexts
        for context_name, content in context_map.items():
            if not content:
                continue

            applicable = self.CONTEXT_RULES.get(context_name, list(self.SEVERITY_MAP.keys()))
            active = [c for c in applicable if c in self._enabled_categories]
            decoded_versions = PayloadNormalizer.normalize(content, max_depth=3)

            for category in active:
                for decoded_content in decoded_versions:
                    matches = self._check_patterns(decoded_content, category)
                    for pattern, matched_text in matches:
                        signals.append(DetectionResult(
                            is_malicious=True,
                            attack_type=category,
                            pattern_matched=pattern,
                            details=f"Pattern in {context_name}: {matched_text[:50]}",
                            severity=self.SEVERITY_MAP.get(category, 'medium'),
                            context=context_name
                        ))

        # Protocol attacks
        if 'protocol_attacks' in self._enabled_categories:
            matches = self._check_patterns(method, 'protocol_attacks')
            for pattern, matched_text in matches:
                signals.append(DetectionResult(
                    is_malicious=True,
                    attack_type='protocol_attacks',
                    pattern_matched=pattern,
                    details=f"Suspicious method: {method}",
                    severity='medium',
                    context='method'
                ))

        return signals

    def check_response(self, response_data: Dict[str, Any]) -> DetectionResult:
        """
        Check response for data leakage (paranoia level 4 only)
        """
        if self.paranoia_level < 4:
            return DetectionResult(is_malicious=False)

        body = response_data.get('body', '')

        sensitive_patterns = [
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+', 'Password exposure'),
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+', 'API key exposure'),
            (r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*\S+', 'Secret key exposure'),
            (r'(?i)BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY', 'Private key exposure'),
            (r'(?i)(access[_-]?token|accesstoken)\s*[:=]\s*\S+', 'Access token exposure'),
            (r'(?i)stack\s*trace|traceback|exception\s+in\s+thread', 'Stack trace exposure'),
        ]

        for pattern, description in sensitive_patterns:
            if re.search(pattern, body):
                return DetectionResult(
                    is_malicious=True,
                    attack_type='data_leakage',
                    pattern_matched=pattern,
                    details=description,
                    severity='high',
                    context='response'
                )

        return DetectionResult(is_malicious=False)


# =============================================================================
# Module-level convenience functions
# =============================================================================

_engine = None


def _get_engine() -> WAFEngine:
    global _engine
    if _engine is None:
        _engine = WAFEngine()
    return _engine


def is_malicious_request(data: Dict) -> bool:
    """Check if a request contains malicious content"""
    engine = _get_engine()
    result = engine.check_request(data)
    return result.is_malicious


def get_detection_result(data: Dict) -> DetectionResult:
    """Get detailed detection result for a request"""
    engine = _get_engine()
    return engine.check_request(data)


def get_all_signals(data: Dict) -> List[DetectionResult]:
    """Get ALL detection signals for risk scoring"""
    engine = _get_engine()
    return engine.check_request_all_signals(data)
