@echo off
setlocal
cd /d "%~dp0"

REM This BAT file, run_blackcube.py, and the blackcube package must be together.
if not exist "blackcube\app.py" (
    echo ERROR: Run this script from your extracted BlackCube project root.
    echo Expected blackcube\app.py next to build_windows_exe.bat.
    goto :failed
)
if not exist "run_blackcube.py" (
    echo ERROR: run_blackcube.py is missing from the project root.
    echo Copy the run_blackcube.py file from the packaging fix next to this BAT.
    goto :failed
)
if not exist "blackcube\assets\blackcube.ico" (
    echo ERROR: blackcube\assets\blackcube.ico is missing.
    goto :failed
)
if not exist ".venv\Scripts\python.exe" (
    echo ERROR: Run setup_windows.bat before building.
    goto :failed
)

echo [BlackCube] Running tests before packaging...
".venv\Scripts\python.exe" -m pytest -q
if errorlevel 1 (
    echo ERROR: Tests failed; build aborted.
    goto :failed
)

echo [BlackCube] Installing PyInstaller...
".venv\Scripts\python.exe" -m pip install "pyinstaller>=6,<7"
if errorlevel 1 (
    echo ERROR: PyInstaller installation failed.
    goto :failed
)

echo [BlackCube] Building Windows executable...
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name BlackCube ^
    --icon "blackcube\assets\blackcube.ico" ^
    --add-data "blackcube\assets;blackcube\assets" ^
    --collect-all pqcrypto ^
    --paths "." ^
    "run_blackcube.py"
if errorlevel 1 (
    echo ERROR: PyInstaller failed; see the output above.
    goto :failed
)

if not exist "dist\BlackCube.exe" (
    echo ERROR: PyInstaller ended without creating dist\BlackCube.exe.
    goto :failed
)

echo.
echo SUCCESS: %CD%\dist\BlackCube.exe
echo Test the executable with a disposable vault before real data.
pause
exit /b 0

:failed
pause
exit /b 1
