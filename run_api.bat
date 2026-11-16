@echo off
title SecureAI Gateway - FastAPI Backend Server
echo ========================================================
echo   SecureAI Gateway - Starting FastAPI Backend Server
echo ========================================================
echo.
cd /d "C:\Projects\SecureAI-Gateway"
"C:\Users\advai\AppData\Local\Programs\Python\Python312\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Backend failed to start.
    pause
)
