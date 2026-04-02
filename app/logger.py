"""
Enhanced WAF Logger v2.0
========================
Improvements over v1.0:
- Decision logging with full signal breakdown
- Correlation ID per request for distributed tracing
- Enhanced structured JSON output with risk scores
- SIEM integration patterns (ELK, Splunk)
- Sensitive data masking preserved from v1.0

Log Entry Format (JSON):
{
    "timestamp": "2026-03-30T12:00:00.000Z",
    "level": "WARNING",
    "event": "waf_decision",
    "correlation_id": "abc123def456",
    "client_ip": "1.2.3.4",
    "method": "POST",
    "path": "/api/login",
    "action": "BLOCK",
    "risk_score": 85.0,
    "top_threat": "sql_injection",
    "signal_count": 3,
    "signals": [...],
    "processing_time_ms": 2.5,
    "user_agent": "..."
}
"""
import logging
import logging.handlers
import re
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any

# Import config - handle both direct and module import
try:
    import config
except ImportError:
    from app import config


# =============================================================================
# Sensitive Data Patterns
# =============================================================================

_SENSITIVE_PATTERNS = re.compile(
    r'(password|passwd|pwd|secret|token|api[_\-]?key|apikey|'
    r'authorization|credentials?|session[_\-]?id|access[_\-]?token|'
    r'refresh[_\-]?token|credit[_\-]?card|ssn|cvv)\s*[=:]\s*\S+',
    re.IGNORECASE
)

_SENSITIVE_PARAMS = frozenset({
    'password', 'passwd', 'pwd', 'secret', 'token', 'api_key',
    'apikey', 'access_token', 'refresh_token', 'session_id',
    'credit_card', 'ssn', 'cvv', 'authorization', 'auth',
    'client_secret', 'private_key',
})


def _sanitize_path(full_path: str) -> str:
    """Remove sensitive query parameters from logged paths"""
    if '?' not in full_path:
        return full_path

    path, query = full_path.split('?', 1)
    sanitized_params = []
    for param in query.split('&'):
        if '=' in param:
            key, value = param.split('=', 1)
            if key.lower().strip() in _SENSITIVE_PARAMS:
                sanitized_params.append(f"{key}=****")
            else:
                sanitized_params.append(param)
        else:
            sanitized_params.append(param)

    return f"{path}?{'&'.join(sanitized_params)}" if sanitized_params else path


def _sanitize_reason(reason: str) -> str:
    """Strip sensitive data from block/allow reasons"""
    return _SENSITIVE_PATTERNS.sub(
        lambda m: m.group(0).split('=')[0] + '=****' if '=' in m.group(0)
        else m.group(0).split(':')[0] + ':****',
        reason
    )


# =============================================================================
# Correlation ID Generation
# =============================================================================

def generate_correlation_id() -> str:
    """Generate a unique correlation ID for request tracing"""
    return str(uuid.uuid4())[:12]


# =============================================================================
# JSON Formatter for structured logging
# =============================================================================

class JSONFormatter(logging.Formatter):
    """Outputs log records as single-line JSON for SIEM ingestion"""

    def format(self, record):
        log_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
        }

        # Include WAF-specific structured data if present
        if hasattr(record, 'waf_data'):
            log_data.update(record.waf_data)
        else:
            log_data['message'] = record.getMessage()

        return json.dumps(log_data, default=str)


# =============================================================================
# Logger Setup
# =============================================================================

def _setup_logger() -> logging.Logger:
    """Configure rotating file + stdout JSON logger"""
    logger = logging.getLogger('waf')

    # Don't add handlers if already configured
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))
    logger.propagate = False

    # Ensure log directory exists
    os.makedirs(config.LOG_DIR, exist_ok=True)

    # Rotating file handler — now uses the config values that were previously ignored
    file_handler = logging.handlers.RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.LOG_MAX_SIZE,         # 10MB default from config
        backupCount=config.LOG_BACKUP_COUNT,  # 5 backups default from config
        encoding='utf-8'
    )
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)

    # Also log to stdout for container/Docker environments
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(JSONFormatter())
    logger.addHandler(stream_handler)

    return logger


# Module-level logger instance
_logger = _setup_logger()


# =============================================================================
# Public API
# =============================================================================

def log_request(request, blocked: bool, reason: str = "Allowed"):
    """
    Log a WAF request with sensitive data masking.

    Args:
        request: Flask request object
        blocked: Whether the request was blocked
        reason: Human-readable reason for the action
    """
    sanitized_path = _sanitize_path(request.full_path)
    sanitized_reason = _sanitize_reason(reason)

    # Build structured log entry
    waf_data = {
        'event': 'waf_request',
        'client_ip': request.remote_addr,
        'method': request.method,
        'path': sanitized_path,
        'status': 'BLOCKED' if blocked else 'ALLOWED',
        'reason': sanitized_reason,
        'user_agent': (request.headers.get('User-Agent', '') or '')[:200],
    }

    # Include correlation ID if present on request
    correlation_id = getattr(request, '_waf_correlation_id', None)
    if correlation_id:
        waf_data['correlation_id'] = correlation_id

    # Create a log record with WAF data attached
    level = logging.WARNING if blocked else logging.INFO
    record = logging.LogRecord(
        name='waf', level=level,
        pathname='logger.py', lineno=0,
        msg=f"{'BLOCKED' if blocked else 'ALLOWED'}: {sanitized_path}",
        args=(), exc_info=None
    )
    record.waf_data = waf_data

    _logger.handle(record)


def log_decision(
    request,
    decision: Any,
    correlation_id: str = "",
):
    """
    Log a WAF decision with full signal breakdown.

    Args:
        request: Flask request object
        decision: Decision object from DecisionEngine
        correlation_id: Request correlation ID for tracing
    """
    sanitized_path = _sanitize_path(request.full_path)

    # Build detailed decision log
    waf_data = {
        'event': 'waf_decision',
        'correlation_id': correlation_id or getattr(request, '_waf_correlation_id', ''),
        'client_ip': request.remote_addr,
        'method': request.method,
        'path': sanitized_path,
        'user_agent': (request.headers.get('User-Agent', '') or '')[:200],
    }

    # Add decision details if it has to_dict
    if hasattr(decision, 'to_dict'):
        decision_dict = decision.to_dict()
        waf_data.update({
            'action': decision_dict.get('action', 'unknown'),
            'risk_score': decision_dict.get('total_score', 0),
            'top_threat': decision_dict.get('top_threat', ''),
            'signal_count': decision_dict.get('signal_count', 0),
            'processing_time_ms': decision_dict.get('processing_time_ms', 0),
            'reason': decision_dict.get('reason', ''),
            'signals': decision_dict.get('signals', []),
        })
    elif hasattr(decision, 'action'):
        action_val = decision.action.value if hasattr(decision.action, 'value') else str(decision.action)
        waf_data.update({
            'action': action_val,
            'risk_score': getattr(decision, 'total_score', 0),
            'top_threat': getattr(decision, 'top_threat', ''),
            'reason': getattr(decision, 'reason', ''),
        })

    # Determine log level based on action
    action = waf_data.get('action', 'allow')
    if action in ('block', 'BLOCK'):
        level = logging.WARNING
    elif action in ('challenge', 'CHALLENGE'):
        level = logging.WARNING
    elif action in ('log', 'LOG'):
        level = logging.INFO
    else:
        level = logging.DEBUG

    record = logging.LogRecord(
        name='waf', level=level,
        pathname='logger.py', lineno=0,
        msg=f"Decision: {action} | Score: {waf_data.get('risk_score', 0):.0f} | {sanitized_path}",
        args=(), exc_info=None
    )
    record.waf_data = waf_data

    _logger.handle(record)


def log_security_event(event_type: str, details: dict):
    """
    Log a security-specific event (login attempt, config change, etc.)

    Args:
        event_type: Type of security event
        details: Dict of event details (will be sanitized)
    """
    waf_data = {
        'event': event_type,
        **{k: _sanitize_reason(str(v)) for k, v in details.items()}
    }

    record = logging.LogRecord(
        name='waf', level=logging.WARNING,
        pathname='logger.py', lineno=0,
        msg=f"Security event: {event_type}",
        args=(), exc_info=None
    )
    record.waf_data = waf_data

    _logger.handle(record)


def log_rule_reload(success: bool, messages: list):
    """Log a rule reload event"""
    waf_data = {
        'event': 'rule_reload',
        'success': success,
        'messages': messages,
    }

    level = logging.INFO if success else logging.ERROR
    record = logging.LogRecord(
        name='waf', level=level,
        pathname='logger.py', lineno=0,
        msg=f"Rule reload: {'success' if success else 'failed'}",
        args=(), exc_info=None
    )
    record.waf_data = waf_data

    _logger.handle(record)


def log_anomaly(
    client_ip: str,
    anomaly_score: float,
    details: str,
    correlation_id: str = "",
):
    """Log an anomaly detection event"""
    waf_data = {
        'event': 'anomaly_detected',
        'client_ip': client_ip,
        'anomaly_score': round(anomaly_score, 1),
        'details': details,
        'correlation_id': correlation_id,
    }

    record = logging.LogRecord(
        name='waf', level=logging.WARNING,
        pathname='logger.py', lineno=0,
        msg=f"Anomaly: score={anomaly_score:.0f} for {client_ip}",
        args=(), exc_info=None
    )
    record.waf_data = waf_data

    _logger.handle(record)
