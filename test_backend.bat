@echo off
echo Testing local backend on port 5001...
echo.

echo 1. Testing health endpoint...
curl -s http://localhost:5001/api/health | findstr /C:"status"
if errorlevel 1 (
    echo ERROR: Backend not running on port 5001
    echo Start backend with: cd backend && python app.py
    goto :end
)
echo Backend is running!

echo.
echo 2. Testing login with default credentials...
curl -s -X POST http://localhost:5001/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"email\":\"admin@soc.local\",\"password\":\"Admin@SOC2024!\"}" | findstr /C:"user"
if errorlevel 1 (
    echo ERROR: Login failed
) else (
    echo Login successful!
)

echo.
echo 3. Testing login with analyst credentials...
curl -s -X POST http://localhost:5001/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"email\":\"analyst@soc.local\",\"password\":\"Analyst@SOC2024!\"}" | findstr /C:"user"
if errorlevel 1 (
    echo ERROR: Analyst login failed
) else (
    echo Analyst login successful!
)

echo.
echo If backend tests pass but frontend fails, fix frontend API URL.
echo Frontend should call: http://localhost:5001/api/auth/login
echo Not: http://localhost:3001/api/auth/login

:end
echo.
pause