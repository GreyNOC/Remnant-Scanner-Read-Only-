@echo off
setlocal
cd /d "%~dp0\.."

set PYTHONPATH=%CD%\src

echo [1/3] Compiling Python files...
python -m compileall -q src tests launch_gui.py
if errorlevel 1 exit /b 1

echo [2/3] Running unit tests...
python -m unittest discover -s tests
if errorlevel 1 exit /b 1

echo [3/3] Running CLI smoke test...
if not exist reports mkdir reports
python launch_gui.py --cli --txt reports\qa_smoke_report.txt --json reports\qa_smoke_report.json
if errorlevel 1 exit /b 1

echo.
echo QA checks passed.
