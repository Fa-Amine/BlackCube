@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo Run setup_windows.bat first.
  pause
  exit /b 1
)
set PYTHONFAULTHANDLER=1
echo [BLACKCUBE] Running with Python fault handler, logging to blackcube-debug.log
.venv\Scripts\python.exe -X faulthandler -m blackcube > blackcube-debug.log 2>&1
set CODE=%errorlevel%
echo [BLACKCUBE] Exit code %CODE% ; log at %cd%\blackcube-debug.log
echo [BLACKCUBE] Review and redact local file names/paths before sharing the log.
pause
exit /b %CODE%
