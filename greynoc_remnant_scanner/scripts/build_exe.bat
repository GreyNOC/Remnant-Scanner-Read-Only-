@echo off
setlocal
cd /d "%~dp0\.."

set PYTHONPATH=%CD%\src

echo Building GreyNOC McAfee Remnant Scanner...
python -m pip install --upgrade pyinstaller
if errorlevel 1 exit /b 1

pyinstaller --onefile --windowed ^
  --name GreyNOC-McAfee-Remnant-Scanner ^
  --icon assets\greynoc_icon.ico ^
  --add-data "assets\greynoc_icon.png;assets" ^
  launch_gui.py

if errorlevel 1 exit /b 1

echo.
echo Build complete: dist\GreyNOC-McAfee-Remnant-Scanner.exe
