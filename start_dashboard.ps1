# WAF Dashboard Startup Script for PowerShell
# ============================================================

# Set the dashboard password (CHANGE THIS!)
$env:WAF_DASHBOARD_PASSWORD = "SecurePassword123!"
$env:WAF_DASHBOARD_USERNAME = "admin"

# Set API key for management endpoints  
$env:WAF_API_KEY = "your-api-key-here"

# Storage backend
$env:WAF_STORAGE_BACKEND = "sqlite"
$env:WAF_SQLITE_DB_PATH = "./data/waf.db"

# Display info
Write-Host ""
Write-Host "============================================================"
Write-Host "  Starting WAF Dashboard on http://127.0.0.1:5001"
Write-Host "  Username: admin"
Write-Host "  Password: (as configured in WAF_DASHBOARD_PASSWORD)"
Write-Host "============================================================"
Write-Host ""

# Start the dashboard
Set-Location $PSScriptRoot
python app/dashboard.py
