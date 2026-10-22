@echo off
rem IPv7 client build. Run from the repo root; the exe lands in dist\IPv7Client.exe.
rem The host program is not in this repository, on purpose.
cd /d "%~dp0"
pyinstaller --onefile --icon=src\ipv7.ico --name IPv7Client src\ipv7_client.py
if errorlevel 1 (echo build failed & exit /b 1)
echo.
echo dist\IPv7Client.exe is ready. Put IPv7.key next to it.
