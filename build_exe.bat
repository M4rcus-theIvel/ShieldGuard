@echo off
setlocal
title Build ShieldGuard.exe
echo === Building ShieldGuard.exe (with UAC Admin manifest) ===
cd /d "%~dp0"

echo [1/3] Checking Python virtual environment and dependencies...
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Khong the tao .venv. Hay kiem tra Python da duoc cai dat chua.
        goto :fail
    )
)

".venv\Scripts\python.exe" -c "import customtkinter, psutil, requests, PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo [*] Dang cai dat thu vien tu requirements.txt va pyinstaller...
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt pyinstaller
    if errorlevel 1 goto :fail
)

echo [2/3] Running automated tests...
".venv\Scripts\python.exe" tests\test_core.py
if errorlevel 1 (
    echo [ERROR] Kiem thu tu dong that bai! Huy dong goi .exe.
    goto :fail
)

echo [3/3] Packaging ShieldGuard.exe with embedded threat_feed.json...
if exist "dist\ShieldGuard.exe" (
    del /f /q "dist\ShieldGuard.exe" >nul 2>&1
    if exist "dist\ShieldGuard.exe" (
        echo [ERROR] dist\ShieldGuard.exe dang chay! Hay dong ShieldGuard truoc khi build cap nhat.
        goto :fail
    )
)

".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name "ShieldGuard" --collect-all customtkinter --add-data "shieldguard\threat_feed.json;shieldguard" main.py
if errorlevel 1 goto :fail
if not exist "dist\ShieldGuard.exe" goto :fail

echo.
echo [OK] Build thanh cong: %~dp0dist\ShieldGuard.exe
if /i not "%~1"=="--nopause" pause
exit /b 0

:fail
echo.
echo [ERROR] Qua trinh tao ShieldGuard.exe that bai!
if /i not "%~1"=="--nopause" pause
exit /b 1
