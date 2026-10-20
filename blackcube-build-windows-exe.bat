@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Run setup_windows.bat first.
    pause
    exit /b 1
)
echo [BlackCube] Running tests before packaging...
.venv\Scripts\python.exe -m pytest -q
if errorlevel 1 (
    echo Tests failed. Build cancelled.
    pause
    exit /b 1
)
echo [BlackCube] Installing Windows packager...
.venv\Scripts\python.exe -m pip install "pyinstaller>=6,<7"
if errorlevel 1 (
    echo Could not install PyInstaller.
    pause
    exit /b 1
)
echo [BlackCube] Building application...
.venv\Scripts\pyinstaller.exe --noconfirm --clean --onefile --windowed ^
    --name BlackCube ^
    --icon "blackcube\assets\blackcube.ico" ^
    --add-data "blackcube\assets;blackcube\assets" ^
    --collect-all pqcrypto ^
    run_blackcube.py
if errorlevel 1 (
    echo Build failed. Check errors above.
    pause
    exit /b 1
)
echo [BlackCube] Windows executable created: dist\BlackCube.exe
echo Remember: building an EXE does not constitute a security audit.
pause
