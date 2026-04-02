@echo off
REM ============================================================
REM WAF Dashboard Startup Script for Windows
REM ============================================================

REM Set the dashboard password (CHANGE THIS!)
set WAF_DASHBOARD_PASSWORD=SecurePassword123!
set WAF_DASHBOARD_USERNAME=admin

REM Set API key for management endpoints
set WAF_API_KEY=your-api-key-here

REM Storage backend
set WAF_STORAGE_BACKEND=sqlite
set WAF_SQLITE_DB_PATH=./data/waf.db

REM Start the dashboard
echo.
echo ============================================================
echo   Starting WAF Dashboard on http://127.0.0.1:5001
echo   Username: admin
echo   Password: (as configured in WAF_DASHBOARD_PASSWORD)
echo ============================================================
echo.

cd /d "%~dp0"
python app/dashboard.py

pause
