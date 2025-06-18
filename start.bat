@echo off
chcp 65001 >nul 2>&1
color 0A
title SecureFileHub Server
cls

:: Define styling
set "BORDER==================================================================="
set "PREFIX=[*]"
set "SUCCESS=[✓]"
set "ERROR=[✗]"
set "INFO=[i]"

echo.
echo %BORDER%
echo.
echo            *** SecureFileHub Server Launcher ***
echo.
echo %BORDER%
echo.

echo %PREFIX% Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo %ERROR% Python not found! Please install Python first.
    echo.
    pause
    exit /b 1
)

:: Get Python version cleanly
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VER=%%i
echo %SUCCESS% Python %PYTHON_VER% detected
echo.

echo %PREFIX% Installing/Updating dependencies...
echo %INFO% This may take a moment...
echo.

:: Suppress pip output and only show summary
pip install flask waitress colorama --quiet --disable-pip-version-check >nul 2>&1
if errorlevel 1 (
    echo %ERROR% Failed to install dependencies
    echo.
    pause
    exit /b 1
)

echo %SUCCESS% Dependencies ready (flask, waitress, colorama)
echo.

echo %PREFIX% Starting SecureFileHub Server...
echo %BORDER%
echo.

:: Start the Python app
python app.py

echo.
echo %BORDER%
echo %INFO% Server stopped. Press any key to exit...
pause >nul