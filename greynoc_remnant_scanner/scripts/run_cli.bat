@echo off
setlocal
cd /d "%~dp0\.."
set PYTHONPATH=%CD%\src
if not exist reports mkdir reports
python launch_gui.py --cli --txt reports\mcafee_report.txt --json reports\mcafee_report.json
