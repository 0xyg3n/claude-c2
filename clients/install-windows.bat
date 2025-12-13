@echo off
REM MCP Remote Agent Client - Windows Installer
REM This script sets up and runs the agent on Windows

echo.
echo ============================================
echo   MCP Remote Agent Client - Windows Setup
echo ============================================
echo.

REM Check if Node.js is installed
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed!
    echo Please download and install Node.js from: https://nodejs.org/
    pause
    exit /b 1
)

echo [OK] Node.js found:
node --version

REM Create directory if it doesn't exist
if not exist "%USERPROFILE%\mcp-agent" mkdir "%USERPROFILE%\mcp-agent"
cd /d "%USERPROFILE%\mcp-agent"

echo.
echo [INFO] Installing dependencies...
echo {"name":"mcp-agent","type":"module","dependencies":{"ws":"^8.18.3"}} > package.json
call npm install

REM Download the agent file
echo.
echo [INFO] Creating agent script...

REM The agent.js content will be here - copy it manually or download
echo Please copy agent.js to %USERPROFILE%\mcp-agent\
echo.

echo ============================================
echo   Installation Complete!
echo ============================================
echo.
echo To run the agent:
echo   cd %USERPROFILE%\mcp-agent
echo   node agent.js --server wss://YOUR-SERVER:3102 --secret YOUR-SECRET
echo.

pause
