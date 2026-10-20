BlackCube v0.7.0 alpha packaging entrypoint fix (Windows 11)

1. Close BlackCube.
2. Open the folder that contains your build_windows_exe.bat, setup_windows.bat,
   blackcube\app.py, and .venv directory.
3. Copy both run_blackcube.py and build_windows_exe.bat from this patch into
   that folder. Replace the old BAT if prompted.
4. Double-click build_windows_exe.bat.
5. The completed executable should appear at dist\BlackCube.exe.

Important: The previous source ZIP already included run_blackcube.py, but
using the separately downloaded BAT or copying only some files can leave
it out. Do not put run_blackcube.py inside the inner blackcube package;
it belongs next to build_windows_exe.bat.

This changes only the launcher and build script. It does not alter encryption
code or existing vaults. Executable packaging is not a security audit.
