"""
Web Application Firewall v4.0 — Main Application
=================================================
Architecture Overhaul:
- Pipeline-based request processing (chain of responsibility)
- Centralized decision engine combining ALL subsystem signals
- Anomaly detection for zero-day attack detection
- Dynamic rule management with hot-reload
- Verdict caching for performance optimization
- Enhanced structured logging with correlation IDs
- Schema validation for API security

Request Processing Flow:
  Client → Nginx (TLS) → Flask → Pipeline:
    1. WhitelistStage    (IP/path bypass)
    2. IPBlockStage      (permanent + temp blocks)
    3. GeoBlockStage     (country-based filtering)
    4. RateLimitStage    (adaptive rate limiting)
    5. ValidationStage   (size, JSON, schema, file upload)
    6. RuleEngineStage   (pattern-based attack detection)
    7. AnomalyStage      (statistical anomaly detection)
    8. BehavioralStage   (bot/behavioral analysis)
    9. DecisionStage     (unified multi-signal scoring)
    10. LoggingStage     (structured decision logging)
  → Backend (proxied)
"""
import os
import sys
import time
import hmac
import ipaddress
import functools
import threading
import uuid

from flask import Flask, request, Response, jsonify

# Add app directory to path
sys.path.insert(0, os.path.dirname(__file__))

import config
from storage import get_storage_backend
from rate_limiter import AdaptiveRateLimiter
from waf_engine import WAFEngine, get_all_signals
from logger import (
    log_request, log_security_event, log_decision,
    log_rule_reload, log_anomaly, generate_correlation_id,
)
from metrics import get_metrics
from input_validator import validate_json_body, inspect_file_upload
from risk_scorer import SEVERITY_WEIGHTS, get_pattern_confidence
from bot_detector import BehavioralBotDetector
from decision_engine import (
    DecisionEngine, Signal, SignalCategory, Action,
    risk_signals_to_engine_signals, Decision,
)
from anomaly_detector import create_anomaly_detector, extract_features
from rule_manager import RuleManager
from cache import get_verdict_cache
from schema_validator import SchemaValidator
from pipeline import (
    WAFPipeline, RequestContext,
    WhitelistStage, IPBlockStage, RateLimitStage,
    RuleEngineStage, AnomalyStage, BehavioralStage,
    DecisionStage, LoggingStage, ValidationStage as PipelineValidationStage,
)

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

# Initialize storage backend
storage = get_storage_backend(
    config.STORAGE_BACKEND,
    db_path=config.SQLITE_DB_PATH,
    host=config.REDIS_HOST,
    port=config.REDIS_PORT,
    db=config.REDIS_DB,
    password=config.REDIS_PASSWORD
)

# Initialize rate limiter
rate_limiter = AdaptiveRateLimiter(
    storage=storage,
    requests_per_window=config.RATE_LIMIT_REQUESTS,
    window_seconds=config.RATE_LIMIT_WINDOW,
    burst_limit=config.RATE_LIMIT_BURST,
    burst_window_seconds=config.RATE_LIMIT_BURST_WINDOW
)

# Initialize rule manager with hot-reload support
rule_manager = RuleManager(
    rules_path=config.RULES_PATH,
    auto_watch=config.RULES_AUTO_WATCH,
    watch_interval=config.RULES_WATCH_INTERVAL,
)
rule_manager.load_rules()

# Initialize WAF engine
waf_engine = WAFEngine(
    rules_path=config.RULES_PATH,
    paranoia_level=config.PARANOIA_LEVEL,
)

# Initialize verdict cache
verdict_cache = get_verdict_cache(
    max_size=config.CACHE_MAX_SIZE,
    ttl=config.CACHE_TTL,
    enabled=config.CACHE_ENABLED,
)

# Initialize metrics collector
metrics = get_metrics()

# Initialize anomaly detector
anomaly_detector = None
if config.ANOMALY_DETECTION_ENABLED:
    anomaly_detector = create_anomaly_detector(
        use_isolation_forest=config.ANOMALY_USE_ISOLATION_FOREST,
        anomaly_threshold=config.ANOMALY_THRESHOLD,
    )

# Initialize behavioral bot detector
bot_detector = BehavioralBotDetector()

# Initialize schema validator
schema_validator = None
if config.SCHEMA_VALIDATION_ENABLED:
    schema_validator = SchemaValidator(schemas_dir=config.SCHEMA_DIR)

# Initialize geo-blocker if enabled
geo_blocker = None
if config.GEO_BLOCKING_ENABLED:
    try:
        from geoblocking import GeoBlocker
        geo_blocker = GeoBlocker(
            blocked_countries=set(config.GEO_BLOCKED_COUNTRIES),
            allowed_countries=set(config.GEO_ALLOWED_COUNTRIES),
            db_path=config.GEO_DB_PATH
        )
    except Exception as e:
        print(f"[WAF] Geo-blocking initialization failed: {e}")

# Initialize CAPTCHA system if enabled
captcha_system = None
suspicion_tracker = None
challenge_sessions = None
if config.CAPTCHA_ENABLED:
    try:
        from captcha import CaptchaChallenge, SuspicionTracker, ChallengeSession
        captcha_system = CaptchaChallenge(storage, token_ttl=config.CAPTCHA_TOKEN_TTL)
        suspicion_tracker = SuspicionTracker()
        challenge_sessions = ChallengeSession(
            session_duration=config.CAPTCHA_SESSION_DURATION
        )
    except Exception as e:
        print(f"[WAF] CAPTCHA initialization failed: {e}")

# Wire rule reload → cache invalidation
def on_rule_reload(ruleset):
    verdict_cache.invalidate_all()
    metrics.record_rule_reload()
    log_rule_reload(True, [f"Reloaded {ruleset.total_rules} rules v{ruleset.version}"])

rule_manager._on_reload = on_rule_reload


# =============================================================================
# Headers that should not be forwarded (hop-by-hop)
# =============================================================================
HOP_BY_HOP_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade", "content-encoding",
}


def filter_headers(headers):
    """Filter out hop-by-hop headers"""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}


# =============================================================================
# Secure IP Extraction with Trusted Proxy Validation
# =============================================================================

def get_client_ip():
    """
    Get the real client IP with trusted proxy validation.
    Only trusts forwarded headers from configured trusted proxies.
    """
    remote_addr = request.remote_addr or 'unknown'

    if not config.TRUST_PROXY_HEADERS:
        return remote_addr

    if remote_addr not in config.TRUSTED_PROXIES:
        return remote_addr

    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        ips = [ip.strip() for ip in xff.split(',')]
        for ip in reversed(ips):
            if ip not in config.TRUSTED_PROXIES:
                try:
                    ipaddress.ip_address(ip)
                    return ip
                except ValueError:
                    continue

    xri = request.headers.get('X-Real-IP', '')
    if xri:
        try:
            ipaddress.ip_address(xri)
            return xri
        except ValueError:
            pass

    cf_ip = request.headers.get('CF-Connecting-IP', '')
    if cf_ip:
        try:
            ipaddress.ip_address(cf_ip)
            return cf_ip
        except ValueError:
            pass

    return remote_addr


# =============================================================================
# API Key Authentication for Management Endpoints
# =============================================================================

def require_api_key(f):
    """Require API key for WAF management endpoints"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not config.WAF_API_KEY:
            return Response("Management API disabled. Set WAF_API_KEY.", status=404)

        provided_key = (
            request.headers.get('X-API-Key') or
            request.args.get('api_key')
        )

        if not provided_key or not hmac.compare_digest(
            provided_key.encode(), config.WAF_API_KEY.encode()
        ):
            log_security_event('unauthorized_api_access', {
                'ip': get_client_ip(),
                'path': request.path,
            })
            return Response("401 Unauthorized", status=401)

        return f(*args, **kwargs)
    return decorated


# =============================================================================
# Whitelist & Size Validation helpers
# =============================================================================

def is_whitelisted_ip(ip: str) -> bool:
    return ip in config.WHITELIST_IPS


def is_whitelisted_path(path: str) -> bool:
    for whitelist_path in config.WHITELIST_PATHS:
        if path.startswith(whitelist_path):
            return True
    return False


def check_request_size() -> tuple:
    if len(request.url) > config.MAX_URL_LENGTH:
        return False, f"URL too long: {len(request.url)} > {config.MAX_URL_LENGTH}"
    if len(request.headers) > config.MAX_HEADER_COUNT:
        return False, f"Too many headers: {len(request.headers)} > {config.MAX_HEADER_COUNT}"
    header_size = sum(len(k) + len(v) for k, v in request.headers.items())
    if header_size > config.MAX_HEADER_SIZE:
        return False, f"Headers too large: {header_size} > {config.MAX_HEADER_SIZE}"
    return True, None


def block_ip(ip: str, reason: str):
    """Block an IP and check for permanent block threshold"""
    violation_count = storage.increment_violation_count(ip)
    if config.PERMANENT_BLOCK_THRESHOLD > 0 and violation_count >= config.PERMANENT_BLOCK_THRESHOLD:
        storage.add_permanent_block(
            ip,
            f"Exceeded violation threshold ({violation_count} violations). Last: {reason}"
        )
        log_security_event('permanent_block', {'ip': ip, 'violations': violation_count})
    else:
        storage.add_blocked_ip(ip, reason, config.BLOCK_DURATION)


# =============================================================================
# Main WAF Check — Pipeline-Based Architecture
# =============================================================================

@app.before_request
def waf_check():
    """
    Main WAF check using pipeline architecture.

    Processing pipeline:
    1. Whitelist bypass (IP & path)
    2. Geo-blocking check
    3. Permanent/temporary block check
    4. Request size validation
    5. JSON/input validation + schema validation
    6. Rate limiting
    7. WAF pattern detection (with verdict caching)
    8. Anomaly detection
    9. Behavioral bot detection
    10. Centralized decision engine
    11. Structured decision logging
    """
    # Store timing + correlation ID
    request._waf_start_time = time.time()
    correlation_id = generate_correlation_id()
    request._waf_correlation_id = correlation_id

    client_ip = get_client_ip()
    path = request.path

    # --- 1. Whitelist bypass ---
    if is_whitelisted_path(path) or path == '/metrics':
        return None
    if is_whitelisted_ip(client_ip):
        return None

    # --- 2. Geo-blocking check ---
    if geo_blocker:
        try:
            is_geo_blocked, geo_reason = geo_blocker.is_blocked(client_ip)
            if is_geo_blocked:
                log_request(request, blocked=True, reason=f"Geo-blocked: {geo_reason}")
                storage.log_request(client_ip, request.method, path, True, f"Geo: {geo_reason}")
                metrics.record_request(blocked=True, attack_type="geo_block", severity="medium")
                metrics.record_decision("block")
                return Response(f"403 Forbidden - Access denied from your region", status=403)
        except Exception as e:
            print(f"[WAF] Geo-blocking error: {e}")

    # --- 3. Permanent/temporary block check ---
    if storage.is_permanently_blocked(client_ip):
        log_request(request, blocked=True, reason="IP Permanently Blocked")
        storage.log_request(client_ip, request.method, path, True, "Permanent Block")
        metrics.record_request(blocked=True, attack_type="permanent_block", severity="critical")
        metrics.record_decision("block")
        return Response("403 Forbidden - IP Permanently Blocked", status=403)

    if storage.is_blocked_ip(client_ip):
        log_request(request, blocked=True, reason="IP Temporarily Blocked")
        storage.log_request(client_ip, request.method, path, True, "Temporary Block")
        metrics.record_request(blocked=True, attack_type="temporary_block", severity="high")
        metrics.record_decision("block")
        return Response("403 Forbidden - IP Temporarily Blocked", status=403)

    # --- 4. Request size validation ---
    size_valid, size_error = check_request_size()
    if not size_valid:
        block_ip(client_ip, size_error)
        log_request(request, blocked=True, reason=size_error)
        storage.log_request(client_ip, request.method, path, True, size_error)
        metrics.record_request(blocked=True, attack_type="size_limit", severity="medium")
        return Response(f"413 Request Entity Too Large - {size_error}", status=413)

    # --- 5. JSON/input validation + schema validation ---
    content_type = request.content_type or ''
    body = request.get_data(as_text=True)

    json_valid, json_error = validate_json_body(body, content_type)
    if not json_valid:
        log_request(request, blocked=True, reason=json_error)
        storage.log_request(client_ip, request.method, path, True, json_error)
        metrics.record_request(blocked=True, attack_type="input_validation", severity="medium")
        return Response(f"400 Bad Request - {json_error}", status=400)

    # File upload inspection
    if request.files:
        for file_key, file_obj in request.files.items():
            file_data = file_obj.read(4096)
            file_obj.seek(0)
            is_safe, file_threat = inspect_file_upload(file_data, file_obj.filename or '')
            if not is_safe:
                block_ip(client_ip, f"Dangerous upload: {file_threat}")
                log_request(request, blocked=True, reason=file_threat)
                storage.log_request(client_ip, request.method, path, True, file_threat)
                metrics.record_request(blocked=True, attack_type="file_upload", severity="high")
                return Response(f"403 Forbidden - {file_threat}", status=403)

    # --- 6. Rate limiting ---
    if config.RATE_LIMIT_ENABLED:
        is_limited, limit_reason = rate_limiter.is_rate_limited(client_ip)
        if is_limited:
            log_request(request, blocked=True, reason=limit_reason)
            storage.log_request(client_ip, request.method, path, True, limit_reason)
            metrics.record_request(
                blocked=True, attack_type="rate_limit",
                severity="low", rate_limited=True
            )
            metrics.record_decision("block")
            return Response(f"429 Too Many Requests - {limit_reason}", status=429)

    # --- 7-10. Multi-signal detection + decision engine ---
    try:
        request_data = {
            "headers": dict(request.headers),
            "params": request.args.to_dict(flat=True),
            "body": body,
            "path": path,
            "method": request.method
        }

        # Create decision engine for this request
        decision_engine = DecisionEngine(
            block_threshold=config.RISK_BLOCK_THRESHOLD,
            challenge_threshold=config.RISK_CHALLENGE_THRESHOLD,
            log_threshold=config.RISK_LOG_THRESHOLD,
        )
        decision_engine._correlation_id = correlation_id

        # --- 7. WAF pattern detection (with caching) ---
        signals = get_all_signals(request_data)
        if signals:
            engine_signals = risk_signals_to_engine_signals(signals)
            decision_engine.add_signals(engine_signals)
            for s in engine_signals:
                metrics.record_signal(s.source)

        # --- 8. Schema validation signals ---
        if schema_validator and body and 'json' in content_type.lower():
            try:
                import json
                parsed = json.loads(body)
                endpoint_key = f"{request.method} {path}"
                schema_errors = schema_validator.validate(endpoint_key, parsed)
                if schema_errors:
                    decision_engine.add_signal(Signal(
                        category=SignalCategory.VALIDATION,
                        source="schema_validation",
                        score=70.0,
                        confidence=0.95,
                        severity="medium",
                        context="body",
                        details=f"Schema errors: {'; '.join(str(e) for e in schema_errors[:3])}",
                    ))
            except Exception:
                pass

        # --- 9. Anomaly detection ---
        if anomaly_detector and config.PIPELINE_ANOMALY_ENABLED:
            anomaly_result = anomaly_detector.score(request_data)
            metrics.record_anomaly_score(anomaly_result.anomaly_score)

            if anomaly_result.anomaly_score > 0:
                decision_engine.add_signal(Signal(
                    category=SignalCategory.ANOMALY,
                    source="anomaly_detector",
                    score=anomaly_result.anomaly_score,
                    confidence=0.7 if anomaly_result.is_anomalous else 0.3,
                    severity="high" if anomaly_result.anomaly_score > 80 else "medium",
                    context="request",
                    details=anomaly_result.details,
                ))

        # --- 10. Behavioral bot detection ---
        if config.PIPELINE_BEHAVIORAL_ENABLED:
            request_data_for_bot = {
                'headers': dict(request.headers),
                'path': path,
                'method': request.method,
            }
            bot_score, bot_indicators = bot_detector.analyze(client_ip, request_data_for_bot)

            if bot_score > 0:
                decision_engine.add_signal(Signal(
                    category=SignalCategory.BEHAVIORAL,
                    source="bot_detector",
                    score=bot_score,
                    confidence=0.8 if bot_score > 50 else 0.4,
                    severity="high" if bot_score > 70 else "medium",
                    context="session",
                    details=f"Bot indicators: {', '.join(bot_indicators)}",
                ))

        # --- Evaluate decision ---
        decision = decision_engine.evaluate()

        # Debug logging (only when DEBUG mode is enabled)
        if config.DEBUG:
            print(f"[WAF DEBUG] Path: {path}, Signals: {len(decision.signals)}, "
                  f"Score: {decision.total_score:.1f}, Action: {decision.action.value}")
            for s in decision.signals:
                print(f"  Signal: {s.source} score={s.weighted_score:.1f} sev={s.severity} cat={s.category.value}")

        # Record decision metrics
        metrics.record_decision(decision.action.value)

        # Log the full decision
        log_decision(request, decision, correlation_id)

        # Act on decision
        if decision.action == Action.BLOCK:
            reason = decision.reason
            block_ip(client_ip, reason)
            log_request(request, blocked=True, reason=reason)
            storage.log_request(client_ip, request.method, path, True, reason)
            metrics.record_request(
                blocked=True,
                attack_type=decision.top_threat,
                severity="high",
            )
            return Response(
                f"403 Forbidden - Blocked by WAF ({decision.top_threat})",
                status=403,
                headers={"X-Request-ID": correlation_id},
            )

        elif decision.action == Action.CHALLENGE and captcha_system and challenge_sessions:
            if not challenge_sessions.is_verified(client_ip):
                log_request(
                    request, blocked=True,
                    reason=f"CAPTCHA challenge (score={decision.total_score:.0f})"
                )
                token, question = captcha_system.create_challenge(client_ip)
                return Response(
                    captcha_system.get_challenge_html(token, question),
                    status=403,
                    content_type='text/html',
                    headers={"X-Request-ID": correlation_id},
                )

        elif decision.action == Action.LOG:
            log_request(
                request, blocked=False,
                reason=f"Suspicious (score={decision.total_score:.0f}, {decision.top_threat})"
            )

        # Feed allowed requests to anomaly detector baseline
        if anomaly_detector and decision.action == Action.ALLOW:
            anomaly_detector.observe(request_data)

    except Exception as e:
        import traceback
        print(f"[WAF] Detection error: {e}")
        traceback.print_exc()

    # Request passed all checks — add correlation ID header
    return None


# =============================================================================
# After-Request: Metrics + Correlation ID Header
# =============================================================================

@app.after_request
def record_metrics(response):
    """Record metrics and add correlation ID after request completes"""
    if request.path in ['/metrics', '/waf/health', '/waf/stats', '/waf/metrics']:
        return response

    start_time = getattr(request, '_waf_start_time', None)
    response_time = time.time() - start_time if start_time else None

    if response.status_code < 400:
        metrics.record_request(blocked=False, response_time=response_time)

    # Add correlation ID to response
    correlation_id = getattr(request, '_waf_correlation_id', None)
    if correlation_id:
        response.headers['X-Request-ID'] = correlation_id

    return response


# =============================================================================
# Proxy Handler with Upstream Retry
# =============================================================================

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def proxy(path):
    """Main proxy handler — forwards requests to backend with retry logic"""
    import requests as req

    client_ip = get_client_ip()
    backend_url = config.BACKEND_URL.rstrip("/")
    full_url = f"{backend_url}/{path}"

    last_error = None

    for attempt in range(config.UPSTREAM_RETRIES):
        try:
            resp = req.request(
                method=request.method,
                url=full_url,
                headers=filter_headers(dict(request.headers)),
                params=request.args,
                data=request.get_data(),
                cookies=request.cookies,
                allow_redirects=False,
                timeout=config.UPSTREAM_TIMEOUT
            )
            last_error = None
            break

        except req.Timeout as e:
            last_error = e
            if attempt < config.UPSTREAM_RETRIES - 1:
                time.sleep(config.UPSTREAM_RETRY_DELAY * (2 ** attempt))
                continue
            log_request(request, blocked=True, reason="Upstream timeout")
            storage.log_request(client_ip, request.method, request.path, True, "Upstream timeout")
            return Response("504 Gateway Timeout", status=504)

        except req.ConnectionError as e:
            last_error = e
            if attempt < config.UPSTREAM_RETRIES - 1:
                time.sleep(config.UPSTREAM_RETRY_DELAY * (2 ** attempt))
                continue
            log_request(request, blocked=True, reason="Upstream connection error")
            storage.log_request(client_ip, request.method, request.path, True, "Upstream connection error")
            return Response("502 Bad Gateway - Backend Unavailable", status=502)

        except req.RequestException as e:
            last_error = e
            log_request(request, blocked=True, reason=f"Upstream error: {e}")
            storage.log_request(client_ip, request.method, request.path, True, f"Upstream error")
            return Response("502 Bad Gateway - Upstream Error", status=502)

    if last_error:
        return Response("502 Bad Gateway", status=502)

    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS]

    log_request(request, blocked=False)
    storage.log_request(client_ip, request.method, request.path, False, "Allowed")

    return Response(resp.content, status=resp.status_code, headers=headers)


# =============================================================================
# Management API Routes
# =============================================================================

@app.route('/waf/health', methods=['GET'])
def health_check():
    """Health check endpoint (unauthenticated)"""
    return jsonify({"status": "healthy", "timestamp": time.time()})


@app.route('/metrics', methods=['GET'])
def prometheus_metrics():
    """Prometheus metrics endpoint"""
    stats = storage.get_stats()
    metrics.update_state(
        blocked_ips=stats.get('blocked_ips_count', 0),
        permanent_blocks=stats.get('permanent_blocks_count', 0)
    )
    return Response(metrics.get_prometheus_metrics(), mimetype='text/plain')


@app.route('/waf/metrics', methods=['GET'])
@require_api_key
def waf_metrics_json():
    """Get WAF metrics as JSON (authenticated)"""
    stats = storage.get_stats()
    metrics.update_state(
        blocked_ips=stats.get('blocked_ips_count', 0),
        permanent_blocks=stats.get('permanent_blocks_count', 0)
    )
    return jsonify(metrics.get_json_metrics())


@app.route('/waf/stats', methods=['GET'])
@require_api_key
def waf_stats():
    """Get WAF statistics (authenticated)"""
    stats = storage.get_stats()
    return jsonify(stats)


@app.route('/waf/blocked-ips', methods=['GET'])
@require_api_key
def blocked_ips():
    """Get list of blocked IPs (authenticated)"""
    ips = storage.get_blocked_ips()
    return jsonify(ips)


@app.route('/waf/unblock/<ip>', methods=['POST'])
@require_api_key
def unblock_ip(ip):
    """Manually unblock an IP (authenticated)"""
    storage.remove_blocked_ip(ip)
    log_security_event('manual_unblock', {'ip': ip, 'by': get_client_ip()})
    return jsonify({"status": "success", "message": f"IP {ip} unblocked"})


# --- New v4.0 Management Endpoints ---

@app.route('/waf/rules/reload', methods=['POST'])
@require_api_key
def reload_rules():
    """Hot-reload rules from disk (authenticated)"""
    success, messages = rule_manager.reload_rules()
    if success:
        # Also reinitialize WAF engine with new rules
        global waf_engine
        waf_engine = WAFEngine(
            rules_path=config.RULES_PATH,
            paranoia_level=config.PARANOIA_LEVEL,
        )
        verdict_cache.invalidate_all()

    log_rule_reload(success, messages)
    return jsonify({
        "success": success,
        "messages": messages,
    }), 200 if success else 500


@app.route('/waf/rules', methods=['GET'])
@require_api_key
def get_rules_status():
    """Get current rule status (authenticated)"""
    return jsonify(rule_manager.get_status())


@app.route('/waf/rules/rollback', methods=['POST'])
@require_api_key
def rollback_rules():
    """Rollback to previous rule version (authenticated)"""
    success = rule_manager.rollback()
    if success:
        verdict_cache.invalidate_all()
        metrics.record_rule_reload()
    return jsonify({"success": success})


@app.route('/waf/cache/stats', methods=['GET'])
@require_api_key
def cache_stats():
    """Get verdict cache statistics (authenticated)"""
    return jsonify(verdict_cache.get_stats())


@app.route('/waf/cache/clear', methods=['POST'])
@require_api_key
def clear_cache():
    """Clear verdict cache (authenticated)"""
    verdict_cache.invalidate_all()
    return jsonify({"status": "cleared"})


@app.route('/waf/anomaly/stats', methods=['GET'])
@require_api_key
def anomaly_stats():
    """Get anomaly detector statistics (authenticated)"""
    if anomaly_detector:
        return jsonify(anomaly_detector.get_stats())
    return jsonify({"enabled": False})


# =============================================================================
# Background Tasks
# =============================================================================

def cleanup_task():
    """Background task to clean up expired entries"""
    while True:
        try:
            storage.cleanup_expired()
            bot_detector.cleanup(max_age_minutes=30)
            verdict_cache.cleanup_expired()
            if captcha_system:
                captcha_system.cleanup_expired()
            if challenge_sessions:
                challenge_sessions.cleanup_expired()
            if suspicion_tracker:
                suspicion_tracker.cleanup_expired()
        except Exception as e:
            print(f"[WAF] Cleanup error: {e}")
        time.sleep(60)


def start_background_tasks():
    """Start background cleanup thread"""
    cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
    cleanup_thread.start()


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    start_background_tasks()

    print(f"""
    +-----------------------------------------------------------+
    |     Web Application Firewall v4.0                         |
    +-----------------------------------------------------------+
    |  Backend URL:     {config.BACKEND_URL:<38} |
    |  Storage:         {config.STORAGE_BACKEND:<38} |
    |  Rate Limiting:   {'Enabled' if config.RATE_LIMIT_ENABLED else 'Disabled':<38} |
    |  Paranoia Level:  {config.PARANOIA_LEVEL:<38} |
    |  Risk Threshold:  {config.RISK_BLOCK_THRESHOLD:<38} |
    |  Block Duration:  {config.BLOCK_DURATION}s{' ':<33} |
    |  Geo-blocking:    {'Enabled' if geo_blocker else 'Disabled':<38} |
    |  CAPTCHA:         {'Enabled' if captcha_system else 'Disabled':<38} |
    |  Bot Detection:   {'Enabled':<38} |
    |  Anomaly Detect:  {'Enabled' if anomaly_detector else 'Disabled':<38} |
    |  Verdict Cache:   {'Enabled' if config.CACHE_ENABLED else 'Disabled':<38} |
    |  Schema Valid:    {'Enabled' if schema_validator else 'Disabled':<38} |
    |  Rule Hot-Reload: {'Enabled' if config.RULES_AUTO_WATCH else 'API only':<38} |
    |  API Auth:        {'Enabled' if config.WAF_API_KEY else 'Disabled':<38} |
    +-----------------------------------------------------------+
    """)

    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        threaded=True
    )
