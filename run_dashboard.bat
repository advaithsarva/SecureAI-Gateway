@echo off
title SecureAI Gateway - Streamlit SOC Dashboard
echo ========================================================
echo   SecureAI Gateway - Starting Streamlit SOC Dashboard
echo ========================================================
echo.
cd /d "C:\Projects\SecureAI-Gateway"
"C:\Users\advai\AppData\Local\Programs\Python\Python312\python.exe" -m streamlit run app/dashboard.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Dashboard failed to start.
    pause
)
