@echo off
rem Build a standalone CyberShield GUI executable for Windows.
rem Usage: build\gui.bat [--install]
setlocal
cd /d %~dp0\..

if "%1"=="--install" (
    echo ^>^> Creating venv and installing build dependencies...
    py -m venv .venv
    call .venv\Scripts\activate.bat
    python -m pip install --upgrade pip
    python -m pip install pyinstaller -r requirements-gui.txt
) else (
    if not exist .venv\Scripts\python.exe (
        echo No virtualenv found. Run gui.bat --install first.
        exit /b 1
    )
    call .venv\Scripts\activate.bat
)

echo ^>^> Building GUI bundle with PyInstaller...
python -m PyInstaller --noconfirm --clean packaging\cybershield-gui.spec

echo.
echo ^>^> Build complete. Artifacts:
dir dist\cybershield-gui.exe