"""
WAF Dashboard v4.0 — Enhanced Admin UI
=======================================
Features:
- Tabbed interface: Overview, Threats, Activity Log, Configuration
- Decision distribution metrics (allow/log/challenge/block)
- Attack type breakdown with severity
- Cache statistics
- Anomaly detection status
- Real-time auto-refresh (30s)
- Log filtering (blocked/allowed)
- Full v4.0 module configuration display
"""
import os
import sys
import hmac
import secrets
import functools
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, Response

# Add app directory to path
sys.path.insert(0, os.path.dirname(__file__))

import config
from storage import get_storage_backend

app = Flask(__name__)
app.secret_key = config.DASHBOARD_SECRET_KEY

# Initialize storage
storage = get_storage_backend(
    config.STORAGE_BACKEND,
    db_path=config.SQLITE_DB_PATH,
    host=config.REDIS_HOST,
    port=config.REDIS_PORT,
    db=config.REDIS_DB,
    password=config.REDIS_PASSWORD
)


# =============================================================================
# CSRF Protection
# =============================================================================

def generate_csrf_token():
    """Generate or retrieve CSRF token for the current session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


# Make csrf_token() available in all Jinja2 templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token


@app.before_request
def csrf_protect():
    """Validate CSRF token on all POST/PUT/DELETE requests"""
    if request.method in ('POST', 'PUT', 'DELETE'):
        if request.path.startswith('/api/') and request.headers.get('X-API-Key'):
            return

        session_token = session.get('csrf_token')
        form_token = (
            request.form.get('csrf_token') or
            request.headers.get('X-CSRF-Token')
        )

        if not session_token or not form_token:
            return Response("403 Forbidden - Missing CSRF token", status=403)

        if not hmac.compare_digest(session_token, form_token):
            return Response("403 Forbidden - Invalid CSRF token", status=403)


# =============================================================================
# Authentication
# =============================================================================

def login_required(f):
    """Decorator to require login for routes"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if not config.DASHBOARD_ENABLED:
        return Response(
            "Dashboard disabled. Set WAF_DASHBOARD_PASSWORD to a secure value.",
            status=503
        )

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if username == config.DASHBOARD_USERNAME and password == config.DASHBOARD_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            session['csrf_token'] = secrets.token_hex(32)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout — clear entire session"""
    session.clear()
    return redirect(url_for('login'))


# =============================================================================
# Helper: Get Metrics Data
# =============================================================================

def _get_metrics_data():
    """Try to get metrics from the metrics module"""
    try:
        from metrics import get_metrics
        m = get_metrics()
        return m.get_json_metrics()
    except Exception:
        return {}


def _get_cache_stats():
    """Try to get cache stats"""
    try:
        from cache import get_verdict_cache
        cache = get_verdict_cache()
        return cache.get_stats()
    except Exception:
        return {"hits": 0, "misses": 0, "hit_rate_percent": 0, "size": 0}


def _get_anomaly_stats():
    """Try to get anomaly detector stats"""
    try:
        from anomaly_detector import create_anomaly_detector
        detector = create_anomaly_detector(use_isolation_forest=False)
        return detector.get_stats()
    except Exception:
        return {"detections": 0, "ready": False}


# =============================================================================
# Dashboard Views
# =============================================================================

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with all v4.0 metrics"""
    stats = storage.get_stats()

    # Get blocked IPs
    blocked_ips = storage.get_blocked_ips()
    for ip_data in blocked_ips:
        if 'blocked_at' in ip_data:
            ip_data['blocked_at_formatted'] = datetime.fromtimestamp(
                ip_data['blocked_at']
            ).strftime('%Y-%m-%d %H:%M:%S')
        if 'expires_at' in ip_data:
            ip_data['expires_at_formatted'] = datetime.fromtimestamp(
                ip_data['expires_at']
            ).strftime('%Y-%m-%d %H:%M:%S')

    # Get permanent blocks
    permanent_blocks = []
    if hasattr(storage, 'get_permanent_blocks'):
        permanent_blocks = storage.get_permanent_blocks()
        for pb in permanent_blocks:
            if 'blocked_at' in pb:
                pb['blocked_at_formatted'] = datetime.fromtimestamp(
                    pb['blocked_at']
                ).strftime('%Y-%m-%d %H:%M:%S')

    # Get recent logs
    recent_logs = []
    if hasattr(storage, 'get_recent_logs'):
        recent_logs = storage.get_recent_logs(100)
        for log in recent_logs:
            if 'timestamp' in log:
                log['timestamp_formatted'] = datetime.fromtimestamp(
                    log['timestamp']
                ).strftime('%Y-%m-%d %H:%M:%S')

    # Get metrics data
    metrics_data = _get_metrics_data()
    cache_stats = _get_cache_stats()
    anomaly_stats = _get_anomaly_stats()

    # Extract decisions from metrics
    decisions = metrics_data.get('decisions', {})

    # Extract attack types from metrics
    attack_types = metrics_data.get('blocked_by_type', {})
    # Fallback: extract from stats if available
    if not attack_types and hasattr(storage, 'get_attack_stats'):
        attack_types = storage.get_attack_stats()

    # Calculate block rate
    total = stats.get('total_requests', 0) or 0
    blocked = stats.get('blocked_requests', 0) or 0
    block_rate = (blocked / total * 100) if total > 0 else 0

    return render_template(
        'dashboard.html',
        stats=stats,
        blocked_ips=blocked_ips,
        permanent_blocks=permanent_blocks,
        recent_logs=recent_logs,
        decisions=decisions,
        attack_types=attack_types,
        block_rate=block_rate,
        cache_stats=cache_stats,
        anomaly_stats=anomaly_stats,
        config={
            'rate_limit_enabled': config.RATE_LIMIT_ENABLED,
            'rate_limit_requests': config.RATE_LIMIT_REQUESTS,
            'rate_limit_window': config.RATE_LIMIT_WINDOW,
            'burst_limit': getattr(config, 'RATE_LIMIT_BURST', 0),
            'block_duration': config.BLOCK_DURATION,
            'paranoia_level': config.PARANOIA_LEVEL,
            'risk_block_threshold': config.RISK_BLOCK_THRESHOLD,
            'backend_url': config.BACKEND_URL,
            'anomaly_enabled': getattr(config, 'ANOMALY_DETECTION_ENABLED', False),
            'behavioral_enabled': getattr(config, 'PIPELINE_BEHAVIORAL_ENABLED', True),
            'schema_enabled': getattr(config, 'SCHEMA_VALIDATION_ENABLED', False),
            'cache_enabled': getattr(config, 'CACHE_ENABLED', False),
        }
    )


# =============================================================================
# API Endpoints (all require login + CSRF)
# =============================================================================

@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for stats"""
    return jsonify(storage.get_stats())


@app.route('/api/blocked-ips')
@login_required
def api_blocked_ips():
    """API endpoint for blocked IPs"""
    return jsonify(storage.get_blocked_ips())


@app.route('/api/unblock/<ip>', methods=['POST'])
@login_required
def api_unblock(ip):
    """API endpoint to unblock an IP (CSRF protected via before_request)"""
    storage.remove_blocked_ip(ip)
    return jsonify({'status': 'success', 'message': f'IP {ip} unblocked'})


@app.route('/api/logs')
@login_required
def api_logs():
    """API endpoint for recent logs"""
    limit = request.args.get('limit', 100, type=int)
    if hasattr(storage, 'get_recent_logs'):
        return jsonify(storage.get_recent_logs(limit))
    return jsonify([])


@app.route('/api/metrics')
@login_required
def api_metrics():
    """API endpoint for full metrics"""
    return jsonify(_get_metrics_data())


@app.route('/api/cache-stats')
@login_required
def api_cache_stats():
    """API endpoint for cache statistics"""
    return jsonify(_get_cache_stats())


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=config.DEBUG)
