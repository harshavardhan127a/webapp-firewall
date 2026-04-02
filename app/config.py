"""
WAF Configuration File
Contains all configurable settings for the Web Application Firewall
"""
import os
import secrets
import warnings

# =============================================================================
# GENERAL SETTINGS
# =============================================================================
DEBUG = os.environ.get('WAF_DEBUG', 'False').lower() == 'true'
HOST = os.environ.get('WAF_HOST', '0.0.0.0')
PORT = int(os.environ.get('WAF_PORT', 5000))

# Backend server URL (the server being protected)
BACKEND_URL = os.environ.get('WAF_BACKEND_URL', 'http://localhost:8082')

# =============================================================================
# TRUSTED PROXY SETTINGS (C1 Fix: IP Spoofing Prevention)
# =============================================================================
# Only trust X-Forwarded-For headers if explicitly enabled
TRUST_PROXY_HEADERS = os.environ.get('WAF_TRUST_PROXY_HEADERS', 'False').lower() == 'true'

# Comma-separated list of trusted proxy IPs that are allowed to set forwarded headers
TRUSTED_PROXIES = set(
    p.strip() for p in
    os.environ.get('WAF_TRUSTED_PROXIES', '').split(',')
    if p.strip()
)

# =============================================================================
# API MANAGEMENT KEY (C3 Fix: Unauthenticated Management Endpoints)
# =============================================================================
# API key required for /waf/stats, /waf/blocked-ips, /waf/unblock endpoints
# If not set, management endpoints return 404
WAF_API_KEY = os.environ.get('WAF_API_KEY', None)

# =============================================================================
# IP BLOCKING SETTINGS
# =============================================================================
# Duration in seconds to block malicious IPs (default: 30 minutes)
BLOCK_DURATION = int(os.environ.get('WAF_BLOCK_DURATION', 1800))

# Permanent block after this many violations (0 = disabled)
PERMANENT_BLOCK_THRESHOLD = int(os.environ.get('WAF_PERMANENT_BLOCK_THRESHOLD', 10))

# =============================================================================
# RATE LIMITING SETTINGS
# =============================================================================
# Enable rate limiting
RATE_LIMIT_ENABLED = os.environ.get('WAF_RATE_LIMIT_ENABLED', 'True').lower() == 'true'

# Maximum requests per window
RATE_LIMIT_REQUESTS = int(os.environ.get('WAF_RATE_LIMIT_REQUESTS', 100))

# Time window in seconds
RATE_LIMIT_WINDOW = int(os.environ.get('WAF_RATE_LIMIT_WINDOW', 60))

# Burst limit (max requests in short burst)
RATE_LIMIT_BURST = int(os.environ.get('WAF_RATE_LIMIT_BURST', 20))

# Burst window in seconds
RATE_LIMIT_BURST_WINDOW = int(os.environ.get('WAF_RATE_LIMIT_BURST_WINDOW', 5))

# =============================================================================
# REQUEST SIZE LIMITS
# =============================================================================
# Maximum request body size in bytes (default: 10MB)
MAX_CONTENT_LENGTH = int(os.environ.get('WAF_MAX_CONTENT_LENGTH', 10 * 1024 * 1024))

# Maximum URL length
MAX_URL_LENGTH = int(os.environ.get('WAF_MAX_URL_LENGTH', 2048))

# Maximum header size in bytes
MAX_HEADER_SIZE = int(os.environ.get('WAF_MAX_HEADER_SIZE', 8192))

# Maximum number of headers
MAX_HEADER_COUNT = int(os.environ.get('WAF_MAX_HEADER_COUNT', 100))

# =============================================================================
# WHITELIST SETTINGS
# =============================================================================
# IPs that should never be blocked (comma-separated)
# Note: Empty string or 'NONE' disables the IP whitelist
_whitelist_raw = os.environ.get('WAF_WHITELIST_IPS', '127.0.0.1')
WHITELIST_IPS = [ip.strip() for ip in _whitelist_raw.split(',') if ip.strip() and ip.strip().upper() != 'NONE']

# Paths that should bypass WAF checks (comma-separated)
WHITELIST_PATHS = os.environ.get('WAF_WHITELIST_PATHS', '/health,/metrics').split(',')

# =============================================================================
# STORAGE SETTINGS
# =============================================================================
# Storage backend: 'memory', 'sqlite', 'redis'
STORAGE_BACKEND = os.environ.get('WAF_STORAGE_BACKEND', 'sqlite')

# SQLite database path
SQLITE_DB_PATH = os.environ.get('WAF_SQLITE_DB_PATH', 
                                os.path.join(os.path.dirname(__file__), '..', 'data', 'waf.db'))

# Redis settings (if using Redis)
REDIS_HOST = os.environ.get('WAF_REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('WAF_REDIS_PORT', 6379))
REDIS_DB = int(os.environ.get('WAF_REDIS_DB', 0))
REDIS_PASSWORD = os.environ.get('WAF_REDIS_PASSWORD', None)

# =============================================================================
# LOGGING SETTINGS
# =============================================================================
LOG_DIR = os.environ.get('WAF_LOG_DIR', 
                         os.path.join(os.path.dirname(__file__), '..', 'logs'))
LOG_FILE = os.path.join(LOG_DIR, 'waf_logs.txt')
LOG_LEVEL = os.environ.get('WAF_LOG_LEVEL', 'INFO')

# Log rotation settings
LOG_MAX_SIZE = int(os.environ.get('WAF_LOG_MAX_SIZE', 10 * 1024 * 1024))  # 10MB
LOG_BACKUP_COUNT = int(os.environ.get('WAF_LOG_BACKUP_COUNT', 5))

# =============================================================================
# DASHBOARD SETTINGS (C4 Fix: Credential Enforcement)
# =============================================================================
DASHBOARD_ENABLED = os.environ.get('WAF_DASHBOARD_ENABLED', 'True').lower() == 'true'
DASHBOARD_USERNAME = os.environ.get('WAF_DASHBOARD_USERNAME', 'admin')
# Default development password - CHANGE IN PRODUCTION via WAF_DASHBOARD_PASSWORD env var
DASHBOARD_PASSWORD = os.environ.get('WAF_DASHBOARD_PASSWORD', 'waf-admin-2024')
DASHBOARD_SECRET_KEY = os.environ.get(
    'WAF_DASHBOARD_SECRET_KEY',
    secrets.token_hex(32)  # Random per-restart if not explicitly set
)

# Enforce secure password at startup (only block truly insecure passwords)
_INSECURE_PASSWORDS = {'', 'admin', 'changeme', 'password', '123456', 'admin123'}
if DASHBOARD_PASSWORD in _INSECURE_PASSWORDS:
    warnings.warn(
        "\n\n" + "=" * 60 + "\n"
        "SECURITY WARNING: Dashboard password is insecure!\n"
        "   Set WAF_DASHBOARD_PASSWORD env var to a strong password.\n"
        "   Dashboard login is DISABLED until configured.\n"
        + "=" * 60 + "\n",
        stacklevel=2
    )
    DASHBOARD_ENABLED = False
else:
    # Show the default password reminder if using the default
    if DASHBOARD_PASSWORD == 'waf-admin-2024':
        print("\n" + "=" * 60)
        print("  Dashboard Default Credentials:")
        print("    Username: admin")
        print("    Password: admin")
        print("  Change via WAF_DASHBOARD_PASSWORD env var in production!")
        print("=" * 60 + "\n")

# =============================================================================
# SECURITY SETTINGS
# =============================================================================
# Enable/disable specific protection modules
PROTECTION_SQL_INJECTION = os.environ.get('WAF_PROTECTION_SQLI', 'True').lower() == 'true'
PROTECTION_XSS = os.environ.get('WAF_PROTECTION_XSS', 'True').lower() == 'true'
PROTECTION_PATH_TRAVERSAL = os.environ.get('WAF_PROTECTION_PATH_TRAVERSAL', 'True').lower() == 'true'
PROTECTION_COMMAND_INJECTION = os.environ.get('WAF_PROTECTION_CMDI', 'True').lower() == 'true'
PROTECTION_XXE = os.environ.get('WAF_PROTECTION_XXE', 'True').lower() == 'true'
PROTECTION_SSRF = os.environ.get('WAF_PROTECTION_SSRF', 'True').lower() == 'true'
PROTECTION_LFI = os.environ.get('WAF_PROTECTION_LFI', 'True').lower() == 'true'
PROTECTION_RFI = os.environ.get('WAF_PROTECTION_RFI', 'True').lower() == 'true'

# Paranoia level (1-4, higher = more strict but more false positives)
PARANOIA_LEVEL = int(os.environ.get('WAF_PARANOIA_LEVEL', 2))

# =============================================================================
# RISK SCORING SETTINGS (H2 Fix: Decision Engine)
# =============================================================================
# Risk score threshold to block a request (0-100)
RISK_BLOCK_THRESHOLD = int(os.environ.get('WAF_RISK_BLOCK_THRESHOLD', 80))

# Risk score threshold to issue CAPTCHA challenge
RISK_CHALLENGE_THRESHOLD = int(os.environ.get('WAF_RISK_CHALLENGE_THRESHOLD', 40))

# Risk score threshold to log (but allow) suspicious requests
RISK_LOG_THRESHOLD = int(os.environ.get('WAF_RISK_LOG_THRESHOLD', 15))

# =============================================================================
# UPSTREAM SETTINGS
# =============================================================================
# Timeout for upstream requests in seconds
UPSTREAM_TIMEOUT = int(os.environ.get('WAF_UPSTREAM_TIMEOUT', 30))

# Retry settings
UPSTREAM_RETRIES = int(os.environ.get('WAF_UPSTREAM_RETRIES', 3))
UPSTREAM_RETRY_DELAY = float(os.environ.get('WAF_UPSTREAM_RETRY_DELAY', 0.5))

# =============================================================================
# CAPTCHA CHALLENGE SETTINGS
# =============================================================================
# Enable CAPTCHA challenges for suspicious (but not malicious) requests
CAPTCHA_ENABLED = os.environ.get('WAF_CAPTCHA_ENABLED', 'False').lower() == 'true'

# Challenge token TTL in seconds
CAPTCHA_TOKEN_TTL = int(os.environ.get('WAF_CAPTCHA_TOKEN_TTL', 300))

# Session duration after passing challenge (seconds)
CAPTCHA_SESSION_DURATION = int(os.environ.get('WAF_CAPTCHA_SESSION_DURATION', 3600))

# Suspicion score threshold to trigger CAPTCHA
CAPTCHA_THRESHOLD = int(os.environ.get('WAF_CAPTCHA_THRESHOLD', 50))

# =============================================================================
# GEO-BLOCKING SETTINGS
# =============================================================================
# Enable geo-blocking
GEO_BLOCKING_ENABLED = os.environ.get('WAF_GEO_BLOCKING_ENABLED', 'False').lower() == 'true'

# Countries to block (comma-separated ISO 3166-1 alpha-2 codes)
# Example: 'CN,RU,KP,IR' to block China, Russia, North Korea, Iran
GEO_BLOCKED_COUNTRIES = [
    c.strip().upper() 
    for c in os.environ.get('WAF_GEO_BLOCKED_COUNTRIES', '').split(',') 
    if c.strip()
]

# Countries to allow (if set, only these countries can access - allowlist mode)
# Leave empty for blocklist mode
GEO_ALLOWED_COUNTRIES = [
    c.strip().upper() 
    for c in os.environ.get('WAF_GEO_ALLOWED_COUNTRIES', '').split(',') 
    if c.strip()
]

# Path to IP geolocation database
GEO_DB_PATH = os.environ.get('WAF_GEO_DB_PATH', 
                              os.path.join(os.path.dirname(__file__), '..', 'data', 'ip2country.csv'))

# =============================================================================
# VERDICT CACHE SETTINGS (Performance Optimization)
# =============================================================================
# Enable/disable verdict caching for repeated payloads
CACHE_ENABLED = os.environ.get('WAF_CACHE_ENABLED', 'True').lower() == 'true'

# Maximum number of cached verdicts
CACHE_MAX_SIZE = int(os.environ.get('WAF_CACHE_MAX_SIZE', 10000))

# Cache entry TTL in seconds (default: 5 minutes)
CACHE_TTL = int(os.environ.get('WAF_CACHE_TTL', 300))

# =============================================================================
# ANOMALY DETECTION SETTINGS
# =============================================================================
# Enable anomaly detection
ANOMALY_DETECTION_ENABLED = os.environ.get('WAF_ANOMALY_ENABLED', 'True').lower() == 'true'

# Anomaly score threshold (0-100, higher = fewer but more confident detections)
ANOMALY_THRESHOLD = float(os.environ.get('WAF_ANOMALY_THRESHOLD', 60.0))

# Use IsolationForest if sklearn is available (otherwise z-score fallback)
ANOMALY_USE_ISOLATION_FOREST = os.environ.get('WAF_ANOMALY_USE_IF', 'True').lower() == 'true'

# =============================================================================
# SCHEMA VALIDATION SETTINGS
# =============================================================================
# Enable JSON schema validation for API endpoints
SCHEMA_VALIDATION_ENABLED = os.environ.get('WAF_SCHEMA_VALIDATION_ENABLED', 'True').lower() == 'true'

# Directory containing endpoint schema definitions
SCHEMA_DIR = os.environ.get('WAF_SCHEMA_DIR',
                            os.path.join(os.path.dirname(__file__), 'schemas'))

# =============================================================================
# RULE MANAGER SETTINGS
# =============================================================================
# Path to rules file
RULES_PATH = os.environ.get('WAF_RULES_PATH',
                            os.path.join(os.path.dirname(__file__), 'rules.json'))

# Enable file watcher for auto-reload of rules
RULES_AUTO_WATCH = os.environ.get('WAF_RULES_AUTO_WATCH', 'False').lower() == 'true'

# File watcher check interval in seconds
RULES_WATCH_INTERVAL = float(os.environ.get('WAF_RULES_WATCH_INTERVAL', 5.0))

# =============================================================================
# PIPELINE SETTINGS
# =============================================================================
# Enable/disable individual pipeline stages
PIPELINE_ANOMALY_ENABLED = os.environ.get('WAF_PIPELINE_ANOMALY', 'True').lower() == 'true'
PIPELINE_BEHAVIORAL_ENABLED = os.environ.get('WAF_PIPELINE_BEHAVIORAL', 'True').lower() == 'true'
PIPELINE_SCHEMA_VALIDATION_ENABLED = os.environ.get('WAF_PIPELINE_SCHEMA', 'True').lower() == 'true'

# Decision engine category weights (JSON string)
DECISION_CATEGORY_WEIGHTS = os.environ.get('WAF_DECISION_WEIGHTS', '')

