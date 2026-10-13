@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv
    if errorlevel 1 exit /b 1
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 exit /b 1
set FLASK_DEBUG=0
echo Open http://127.0.0.1:5000
".venv\Scripts\python.exe" app.py
pause
