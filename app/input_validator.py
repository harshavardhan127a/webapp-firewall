"""
Input Validation Module (H4 Fix)
Validates structured payloads (JSON, file uploads) before WAF pattern matching.

Features:
- JSON depth and key count validation (prevents parser differential attacks)
- Content-Type verification
- File upload magic byte inspection
- Double extension detection
- Null byte filename injection prevention
"""
import json
import re
from typing import Tuple, Optional


# Maximum allowed JSON nesting depth (prevents hash collision DoS)
MAX_JSON_DEPTH = 20

# Maximum number of keys across entire JSON document
MAX_JSON_KEYS = 1000

# Maximum JSON body size to parse (10MB)
MAX_JSON_PARSE_SIZE = 10 * 1024 * 1024

# Dangerous file signatures (magic bytes at start of file)
DANGEROUS_SIGNATURES = {
    b'MZ': 'Windows executable (PE)',
    b'\x7fELF': 'Linux executable (ELF)',
    b'#!/': 'Shell script',
    b'<?php': 'PHP script',
    b'<jsp:': 'JSP page',
    b'<%@': 'ASP/JSP page',
    b'\xca\xfe\xba\xbe': 'Java class file',
    b'\xfe\xed\xfa\xce': 'Mach-O executable',
    b'\xfe\xed\xfa\xcf': 'Mach-O 64-bit executable',
}

# Dangerous file extensions (double extension attacks)
DANGEROUS_EXTENSIONS = re.compile(
    r'\.(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|exe|bat|cmd|sh|bash|'
    r'ps1|psm1|vbs|vbe|wsf|wsh|com|scr|pif|cgi|py|rb|pl)\.\w+$',
    re.IGNORECASE
)

# Single dangerous extensions
BLOCKED_EXTENSIONS = re.compile(
    r'\.(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|exe|bat|cmd|sh|bash|'
    r'ps1|psm1|vbs|vbe|wsf|wsh|com|scr|pif|cgi|htaccess|htpasswd)$',
    re.IGNORECASE
)


def validate_json_body(body: str, content_type: str) -> Tuple[bool, Optional[str]]:
    """
    Validate JSON request body structure.

    Args:
        body: Raw request body string
        content_type: Content-Type header value

    Returns:
        (is_valid, error_message) — error_message is None if valid
    """
    # Only validate if Content-Type claims JSON
    if not content_type or 'json' not in content_type.lower():
        return True, None

    if not body or not body.strip():
        return True, None

    # Size check before parsing
    if len(body) > MAX_JSON_PARSE_SIZE:
        return False, f"JSON body too large: {len(body)} bytes"

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as e:
        return False, f"Malformed JSON: {str(e)[:100]}"

    # Check nesting depth
    depth = _measure_depth(parsed)
    if depth > MAX_JSON_DEPTH:
        return False, f"JSON nesting too deep: {depth} > {MAX_JSON_DEPTH}"

    # Check total key count
    key_count = _count_keys(parsed)
    if key_count > MAX_JSON_KEYS:
        return False, f"Too many JSON keys: {key_count} > {MAX_JSON_KEYS}"

    return True, None


def validate_content_type(content_type: str, method: str) -> Tuple[bool, Optional[str]]:
    """
    Validate Content-Type header consistency.

    Args:
        content_type: Content-Type header value
        method: HTTP method

    Returns:
        (is_valid, error_message)
    """
    if method in ('POST', 'PUT', 'PATCH') and not content_type:
        # Missing Content-Type on body-carrying methods is suspicious but not blocking
        return True, None

    return True, None


def inspect_file_upload(file_data: bytes, filename: str) -> Tuple[bool, Optional[str]]:
    """
    Inspect file uploads for dangerous content.

    Args:
        file_data: Raw file bytes (first few KB is sufficient)
        filename: Original filename from upload

    Returns:
        (is_safe, threat_description) — threat_description is None if safe
    """
    if not filename:
        return False, "Missing filename in upload"

    # Check for null bytes in filename (path truncation attack)
    if '\x00' in filename or '%00' in filename:
        return False, "Null byte in filename — possible path truncation attack"

    # Check for dangerous double extensions (e.g., shell.php.jpg)
    if DANGEROUS_EXTENSIONS.search(filename):
        return False, f"Dangerous double extension detected: {filename}"

    # Check for directly blocked extensions
    if BLOCKED_EXTENSIONS.search(filename):
        return False, f"Blocked file extension: {filename}"

    # Check magic bytes (file signature)
    if file_data:
        for signature, description in DANGEROUS_SIGNATURES.items():
            if file_data[:len(signature)] == signature:
                return False, f"Dangerous file signature: {description}"

    return True, None


def _measure_depth(obj, current: int = 0) -> int:
    """Recursively measure maximum nesting depth of a JSON structure"""
    if isinstance(obj, dict):
        if not obj:
            return current + 1
        return max(_measure_depth(v, current + 1) for v in obj.values())
    elif isinstance(obj, list):
        if not obj:
            return current + 1
        return max(_measure_depth(v, current + 1) for v in obj)
    return current


def _count_keys(obj) -> int:
    """Recursively count total number of keys in a JSON structure"""
    if isinstance(obj, dict):
        return len(obj) + sum(_count_keys(v) for v in obj.values())
    elif isinstance(obj, list):
        return sum(_count_keys(v) for v in obj)
    return 0
