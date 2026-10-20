@echo off
setlocal
cd /d "%~dp0"
echo [BLACKCUBE] Creating isolated Python environment...
py -3 -m venv .venv
if errorlevel 1 (
  echo Python 3.12+ was not detected. Install 64-bit Python from python.org.
  pause
  exit /b 1
)
echo [BLACKCUBE] Installing Qt and crypto dependencies...
.venv\Scripts\python.exe -m pip install -e ".[dev]"
if errorlevel 1 (
  echo Installation failed. Check internet connection and Python version.
  pause
  exit /b 1
)
echo [BLACKCUBE] Running included tests...
.venv\Scripts\python.exe -m pytest -q
if errorlevel 1 (
  echo Some checks FAILED. Do not rely on this build to protect real secrets.
  pause
  exit /b 1
)
echo [BLACKCUBE] Setup complete. Run launch_windows.bat to start.
pause
