@echo off
REM Cybou Application Launcher
REM Sets up the Qt environment and runs the application

echo Starting Cybou...

REM Add Qt to PATH
set PATH=C:\Qt\6.10.0\mingw_64\bin;%PATH%

REM Change to build directory
cd /d "%~dp0build"

REM Run the application
echo Launching cybou.exe...
cybou.exe

pause