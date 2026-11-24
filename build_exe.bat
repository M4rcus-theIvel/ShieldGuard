@echo off
title Build ShieldGuard.exe
echo === Building ShieldGuard.exe (with UAC Admin manifest) ===
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [!] Khong tim thay .venv. Hay chay: python -m venv .venv
    pause
    exit /b 1
)

".venv\Scripts\pip.exe" install --quiet pyinstaller
".venv\Scripts\pyinstaller.exe" ^
    --noconfirm ^
    --onefile ^
    --windowed ^
    --uac-admin ^
    --name "ShieldGuard" ^
    --collect-all customtkinter ^
    main.py

echo.
if exist "dist\ShieldGuard.exe" (
    echo [OK] Build thanh cong: %~dp0dist\ShieldGuard.exe
) else (
    echo [ERROR] Build that bai!
)
pause
