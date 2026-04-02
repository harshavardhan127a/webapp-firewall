# Web Application Firewall (WAF) v2.0

A comprehensive Python-based Web Application Firewall that acts as a reverse proxy, providing protection against common web attacks.

## Features

### Security Protections
- **SQL Injection Detection** - 70+ patterns covering UNION, blind SQLi, time-based attacks
- **XSS Prevention** - 75+ patterns for script injection, event handlers, encodings
- **Path Traversal Protection** - Directory traversal and LFI detection
- **Command Injection Detection** - Shell command and code injection patterns
- **XXE Prevention** - XML External Entity attack detection
- **SSRF Protection** - Server-Side Request Forgery prevention
- **RFI Detection** - Remote File Inclusion patterns
- **LDAP Injection Prevention**
- **HTTP Header Injection Detection**
- **Scanner/Bot Detection** - Known security scanner user agents

### Infrastructure Features
- **Rate Limiting** - Configurable request limits with burst protection
- **Adaptive Rate Limiting** - Stricter limits for IPs with violation history
- **IP Blocking** - Automatic temporary and permanent blocking
- **Persistent Storage** - SQLite or Redis backends
- **IP Whitelist** - Bypass WAF for trusted IPs
- **Path Whitelist** - Bypass WAF for specific paths (health checks, etc.)
- **Request Size Limits** - Protection against oversized requests
- **Configurable Paranoia Levels** - Balance security vs false positives

### Management
- **Web Dashboard** - Real-time monitoring with authentication
- **REST API** - Programmatic access to WAF stats and controls
- **Comprehensive Logging** - All requests logged with details
- **Docker Support** - Production-ready containers

## Quick Start

### Development Mode
```bash
# Install dependencies
pip install -r requirements.txt

# Run the WAF
python app/main_v2.py

# Run the dashboard (separate terminal)
python app/dashboard_v2.py
```

### Production Mode (Docker)
```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f waf
```

### Production Mode (Gunicorn)
```bash
# Install production dependencies
pip install gunicorn gevent

# Run WAF
gunicorn --config gunicorn.conf.py app.main_v2:app

# Run Dashboard
gunicorn --bind 0.0.0.0:5001 --workers 2 app.dashboard_v2:app
```

## Configuration

All settings can be configured via environment variables:

### General Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_DEBUG` | `False` | Enable debug mode |
| `WAF_HOST` | `0.0.0.0` | Host to bind to |
| `WAF_PORT` | `5000` | Port to listen on |
| `WAF_BACKEND_URL` | `http://localhost:8082` | Backend server URL |

### IP Blocking
| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_BLOCK_DURATION` | `1800` | Block duration in seconds (30 min) |
| `WAF_PERMANENT_BLOCK_THRESHOLD` | `10` | Violations before permanent block |

### Rate Limiting
| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_RATE_LIMIT_ENABLED` | `True` | Enable rate limiting |
| `WAF_RATE_LIMIT_REQUESTS` | `100` | Max requests per window |
| `WAF_RATE_LIMIT_WINDOW` | `60` | Window size in seconds |
| `WAF_RATE_LIMIT_BURST` | `20` | Max burst requests |
| `WAF_RATE_LIMIT_BURST_WINDOW` | `5` | Burst window in seconds |

### Request Limits
| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_MAX_CONTENT_LENGTH` | `10485760` | Max body size (10MB) |
| `WAF_MAX_URL_LENGTH` | `2048` | Max URL length |
| `WAF_MAX_HEADER_SIZE` | `8192` | Max total header size |
| `WAF_MAX_HEADER_COUNT` | `100` | Max number of headers |

### Whitelist
| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_WHITELIST_IPS` | `127.0.0.1` | Comma-separated trusted IPs |
| `WAF_WHITELIST_PATHS` | `/health,/metrics` | Comma-separated bypass paths |

### Storage
| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_STORAGE_BACKEND` | `sqlite` | `memory`, `sqlite`, or `redis` |
| `WAF_SQLITE_DB_PATH` | `data/waf.db` | SQLite database path |
| `WAF_REDIS_HOST` | `localhost` | Redis host |
| `WAF_REDIS_PORT` | `6379` | Redis port |
| `WAF_REDIS_PASSWORD` | `None` | Redis password |

### Dashboard
| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_DASHBOARD_USERNAME` | `admin` | Dashboard login username |
| `WAF_DASHBOARD_PASSWORD` | `changeme` | Dashboard login password |
| `WAF_DASHBOARD_SECRET_KEY` | `...` | Flask secret key |

### Security
| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_PARANOIA_LEVEL` | `2` | 1-4 (higher = stricter) |

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│     WAF     │────▶│   Backend   │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
              ┌──────────┐  ┌──────────┐
              │  SQLite  │  │  Redis   │
              │    or    │  │(optional)│
              └──────────┘  └──────────┘
```

## API Endpoints

### WAF Endpoints (Port 5000)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/waf/health` | GET | Health check |
| `/waf/stats` | GET | WAF statistics |
| `/waf/blocked-ips` | GET | List blocked IPs |
| `/waf/unblock/<ip>` | POST | Unblock an IP |

### Dashboard Endpoints (Port 5001)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/login` | GET/POST | Login page |
| `/logout` | GET | Logout |
| `/dashboard` | GET | Main dashboard |
| `/api/stats` | GET | Stats API |
| `/api/blocked-ips` | GET | Blocked IPs API |
| `/api/unblock/<ip>` | POST | Unblock API |
| `/api/logs` | GET | Recent logs API |

## File Structure

```
webapplicationfirewall/
├── app/
│   ├── main_v2.py         # Main WAF application
│   ├── waf_engine_v2.py   # Detection engine
│   ├── storage.py         # Storage backends
│   ├── rate_limiter.py    # Rate limiting
│   ├── config.py          # Configuration
│   ├── dashboard_v2.py    # Dashboard application
│   ├── logger.py          # Logging
│   ├── rules_v2.json      # Detection rules
│   └── templates/
│       ├── login.html
│       └── dashboard_v2.html
├── data/                  # SQLite database
├── logs/                  # Log files
├── requirements.txt
├── gunicorn.conf.py       # Production config
├── Dockerfile.production
├── docker-compose.yml
└── README.md
```

## Upgrading from v1.0

The v2.0 files are named with `_v2` suffix for backward compatibility:
- `main.py` → `main_v2.py`
- `waf_engine.py` → `waf_engine_v2.py`
- `dashboard.py` → `dashboard_v2.py`
- `rules.json` → `rules_v2.json`

To upgrade, simply switch to using the v2 files.

## Security Recommendations

1. **Change default credentials** - Update `WAF_DASHBOARD_USERNAME` and `WAF_DASHBOARD_PASSWORD`
2. **Use HTTPS** - Configure SSL/TLS in production (see gunicorn.conf.py)
3. **Secure Redis** - Set `WAF_REDIS_PASSWORD` if using Redis
4. **Review paranoia level** - Start with level 2, increase if needed
5. **Monitor logs** - Regularly review WAF logs for patterns
6. **Update rules** - Periodically update detection rules

## Limitations

While this WAF provides significant protection, it should not be your only security measure:
- Regex-based detection can be bypassed with sophisticated encoding
- No machine learning or anomaly detection
- Single-node deployment (no clustering without Redis)
- No real-time threat intelligence feeds

Consider using this alongside:
- Network firewalls
- HTTPS/TLS encryption
- Input validation in your application
- Security headers (CSP, HSTS, etc.)
- Regular security audits

## License

MIT License
"# webapp-firewall" 
