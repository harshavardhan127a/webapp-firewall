---
description: How to run and test the WAF project locally
---

# Running & Testing the WAF Project

## Prerequisites
- Python 3.11+
- pip (comes with Python)
- Git (optional, for version control)

## Quick Start — Local Development

### 1. Install Dependencies
// turbo
```
pip install -r requirements.txt
```

### 2. Set Environment Variables (PowerShell)
```powershell
$env:WAF_BACKEND_URL = "http://httpbin.org"
$env:WAF_DASHBOARD_USERNAME = "admin"
$env:WAF_DASHBOARD_PASSWORD = "YourSecurePassword123!"
$env:WAF_DASHBOARD_SECRET_KEY = "your-random-secret-key-here"
$env:WAF_DEBUG = "True"
```

### 3. Run the WAF Server
```
python app/main.py
```
This starts the WAF on port 5000. You'll see the startup banner showing all enabled features.

### 4. Run the Dashboard (separate terminal)
```
python app/dashboard.py
```
This starts the dashboard on port 5001. Open http://localhost:5001 in your browser.

### 5. Run Tests
// turbo
```
python -m pytest tests/ -v
```

### 6. Run Tests with Coverage
```
python -m pytest tests/ -v --cov=app --cov-report=term-missing
```

## Testing Attacks Manually

### Test SQL Injection (should be BLOCKED):
```
curl "http://localhost:5000/test?id=' OR '1'='1"
```

### Test XSS (should be BLOCKED):
```
curl "http://localhost:5000/test?q=<script>alert(1)</script>"
```

### Test Scanner Detection (should be BLOCKED):
```
curl -H "User-Agent: sqlmap/1.0" "http://localhost:5000/test"
```

### Test Normal Request (should be ALLOWED):
```
curl "http://localhost:5000/test?q=hello+world"
```

### Check Health:
```
curl http://localhost:5000/waf/health
```

### Check Metrics:
```
curl http://localhost:5000/metrics
```

## Docker Deployment

### 1. Generate TLS Certificates (Linux/Mac)
```
bash scripts/generate_tls_certs.sh
```

### 2. Build & Run with Docker Compose
```
docker-compose up --build
```

This starts:
- Nginx (ports 80/443) — TLS termination
- WAF (port 5000) — main firewall
- Dashboard (port 5001) — admin UI
- Redis — shared state store
