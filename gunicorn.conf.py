# Gunicorn configuration file for production deployment

import os
import multiprocessing

# Server socket
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "gevent"  # Use gevent for async handling
worker_connections = 1000
timeout = 30
keepalive = 2

# Process naming
proc_name = "waf"

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL/TLS (M2 Fix: configurable via environment variables)
keyfile = os.environ.get('WAF_TLS_KEY', None)
certfile = os.environ.get('WAF_TLS_CERT', None)
if certfile and keyfile:
    ssl_version = 'TLSv1_2'
    ciphers = 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'

# Hooks
def on_starting(server):
    print("WAF Server starting...")

def on_exit(server):
    print("WAF Server stopped.")

def pre_fork(server, worker):
    pass

def post_fork(server, worker):
    """M8 Fix: Start background tasks in each worker after forking"""
    print(f"Worker spawned (pid: {worker.pid})")
    try:
        from app.main import start_background_tasks
        start_background_tasks()
    except Exception as e:
        print(f"Warning: Could not start background tasks: {e}")

def worker_exit(server, worker):
    print(f"Worker exited (pid: {worker.pid})")
