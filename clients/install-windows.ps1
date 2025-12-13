#Requires -Version 5.1
<#
.SYNOPSIS
    MCP Remote Agent Client - Windows PowerShell Installer

.DESCRIPTION
    This script downloads and installs the MCP Remote Agent Client on Windows.
    It can also configure the agent to run as a Windows service.

.PARAMETER ServerUrl
    The WebSocket server URL (e.g., wss://your-server.com:3102)

.PARAMETER ClientSecret
    The client authentication secret

.PARAMETER ClientId
    Optional custom client ID (defaults to hostname)

.PARAMETER InstallAsService
    Install as a Windows service (requires admin)

.EXAMPLE
    .\install-windows.ps1 -ServerUrl "wss://${DOMAIN}:3102" -ClientSecret "your-secret"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,

    [Parameter(Mandatory=$true)]
    [string]$ClientSecret,

    [string]$ClientId = $env:COMPUTERNAME,

    [switch]$InstallAsService
)

$ErrorActionPreference = "Stop"
$InstallDir = "$env:USERPROFILE\mcp-agent"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  MCP Remote Agent Client - Windows Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if Node.js is installed
try {
    $nodeVersion = node --version
    Write-Host "[OK] Node.js found: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Node.js is not installed!" -ForegroundColor Red
    Write-Host "Please download and install Node.js from: https://nodejs.org/" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Or install via winget:" -ForegroundColor Yellow
    Write-Host "  winget install OpenJS.NodeJS.LTS" -ForegroundColor White
    exit 1
}

# Create installation directory
Write-Host ""
Write-Host "[INFO] Creating installation directory: $InstallDir" -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Set-Location $InstallDir

# Create package.json
Write-Host "[INFO] Creating package.json..." -ForegroundColor Yellow
@'
{
  "name": "mcp-agent",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "ws": "^8.18.3"
  }
}
'@ | Out-File -FilePath "package.json" -Encoding UTF8

# Install dependencies
Write-Host "[INFO] Installing dependencies..." -ForegroundColor Yellow
npm install --silent

# Create agent.js
Write-Host "[INFO] Creating agent script..." -ForegroundColor Yellow

# Download agent.js from server or embed it
# For now, we'll create a minimal version that works on Windows

$agentCode = @'
#!/usr/bin/env node
import WebSocket from 'ws';
import os from 'os';
import { exec } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { promisify } from 'util';

const execAsync = promisify(exec);

const config = {
  serverUrl: process.env.MCP_SERVER_URL || 'ws://localhost:3101',
  clientSecret: process.env.MCP_CLIENT_SECRET || 'secret',
  clientId: process.env.MCP_CLIENT_ID || `${os.hostname()}-${process.pid}`,
  reconnectInterval: 5000,
  heartbeatInterval: 30000,
};

for (let i = 2; i < process.argv.length; i++) {
  switch (process.argv[i]) {
    case '--server': case '-s': config.serverUrl = process.argv[++i]; break;
    case '--secret': case '-k': config.clientSecret = process.argv[++i]; break;
    case '--id': case '-i': config.clientId = process.argv[++i]; break;
  }
}

const handlers = {
  async shell(args) {
    const { cmd, cwd = process.cwd(), timeout = 30000 } = args;
    if (!cmd) throw new Error('No command specified');
    console.log(`[Agent] Executing: ${cmd}`);
    try {
      const { stdout, stderr } = await execAsync(cmd, { cwd, timeout, maxBuffer: 10*1024*1024, shell: true });
      return { success: true, stdout: stdout.trim(), stderr: stderr.trim(), exitCode: 0 };
    } catch (e) {
      return { success: false, stdout: e.stdout?.trim()||'', stderr: e.stderr?.trim()||e.message, exitCode: e.code||1 };
    }
  },
  async file_read(args) {
    const { path: p, encoding = 'utf8' } = args;
    const content = await fs.readFile(p, encoding);
    const stats = await fs.stat(p);
    return { success: true, path: p, content, size: stats.size, modified: stats.mtime.toISOString() };
  },
  async file_write(args) {
    const { path: p, content, encoding = 'utf8' } = args;
    await fs.mkdir(path.dirname(p), { recursive: true });
    await fs.writeFile(p, content, encoding);
    const stats = await fs.stat(p);
    return { success: true, path: p, size: stats.size };
  },
  async file_list(args) {
    const { path: p = '.' } = args;
    const entries = await fs.readdir(p, { withFileTypes: true });
    const files = await Promise.all(entries.map(async e => {
      const full = path.join(p, e.name);
      const s = await fs.stat(full).catch(() => null);
      return { name: e.name, path: full, type: e.isDirectory()?'directory':'file', size: s?.size||0 };
    }));
    return { success: true, path: p, files };
  },
  async system_info() {
    return {
      success: true, hostname: os.hostname(), platform: os.platform(), arch: os.arch(),
      release: os.release(), uptime: os.uptime(), totalmem: os.totalmem(), freemem: os.freemem(),
      cpus: os.cpus().length, username: os.userInfo().username, homedir: os.homedir()
    };
  },
  async process_list() {
    const cmd = os.platform() === 'win32' ? 'tasklist /fo csv /nh' : 'ps aux --no-headers';
    const { stdout } = await execAsync(cmd, { maxBuffer: 10*1024*1024 });
    const lines = stdout.trim().split('\n').slice(0, 100);
    const processes = lines.map(line => {
      if (os.platform() === 'win32') {
        const p = line.split(',').map(s => s.replace(/"/g,''));
        return { name: p[0], pid: p[1], memory: p[4] };
      } else {
        const p = line.trim().split(/\s+/);
        return { user: p[0], pid: p[1], cpu: p[2], mem: p[3], command: p.slice(10).join(' ') };
      }
    });
    return { success: true, count: processes.length, processes };
  },
  async status() {
    return {
      success: true, clientId: config.clientId, hostname: os.hostname(),
      platform: os.platform(), uptime: os.uptime(), freemem: os.freemem(),
      totalmem: os.totalmem(), timestamp: new Date().toISOString()
    };
  }
};

class Agent {
  constructor() { this.ws = null; this.hbTimer = null; }

  connect() {
    console.log(`[Agent] Connecting to ${config.serverUrl}...`);
    this.ws = new WebSocket(config.serverUrl);
    this.ws.on('open', () => { console.log('[Agent] Connected'); this.register(); this.startHb(); });
    this.ws.on('message', d => this.handle(JSON.parse(d.toString())));
    this.ws.on('close', () => { console.log('[Agent] Disconnected'); this.stopHb(); this.reconnect(); });
    this.ws.on('error', e => console.error('[Agent] Error:', e.message));
  }

  register() {
    this.send({ type: 'register', clientId: config.clientId, authSecret: config.clientSecret,
      hostname: os.hostname(), platform: os.platform(), arch: os.arch(), username: os.userInfo().username });
  }

  async handle(msg) {
    if (msg.type === 'registered') console.log(`[Agent] Registered as: ${msg.clientId}`);
    else if (msg.type === 'command') {
      const h = handlers[msg.command];
      if (!h) return this.send({ type: 'command_error', commandId: msg.commandId, error: `Unknown: ${msg.command}` });
      try {
        this.send({ type: 'command_response', commandId: msg.commandId, result: await h(msg.args||{}) });
      } catch (e) {
        this.send({ type: 'command_error', commandId: msg.commandId, error: e.message });
      }
    }
  }

  send(d) { if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(d)); }
  startHb() { this.hbTimer = setInterval(() => this.send({ type: 'heartbeat' }), config.heartbeatInterval); }
  stopHb() { if (this.hbTimer) { clearInterval(this.hbTimer); this.hbTimer = null; } }
  reconnect() { setTimeout(() => this.connect(), config.reconnectInterval); }
}

console.log(`\n[MCP Agent] Client ID: ${config.clientId}`);
console.log(`[MCP Agent] Server: ${config.serverUrl}\n`);
new Agent().connect();
'@

$agentCode | Out-File -FilePath "agent.js" -Encoding UTF8

# Create .env file
Write-Host "[INFO] Creating configuration..." -ForegroundColor Yellow
@"
MCP_SERVER_URL=$ServerUrl
MCP_CLIENT_SECRET=$ClientSecret
MCP_CLIENT_ID=$ClientId
"@ | Out-File -FilePath ".env" -Encoding UTF8

# Create run script
Write-Host "[INFO] Creating run script..." -ForegroundColor Yellow
@"
@echo off
cd /d "%~dp0"
node agent.js --server "$ServerUrl" --secret "$ClientSecret" --id "$ClientId"
pause
"@ | Out-File -FilePath "run-agent.bat" -Encoding ASCII

# Create startup shortcut if requested
if ($InstallAsService) {
    Write-Host "[INFO] Creating startup shortcut..." -ForegroundColor Yellow
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\MCP-Agent.lnk")
    $Shortcut.TargetPath = "cmd.exe"
    $Shortcut.Arguments = "/c `"$InstallDir\run-agent.bat`""
    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.WindowStyle = 7  # Minimized
    $Shortcut.Save()
    Write-Host "[OK] Startup shortcut created" -ForegroundColor Green
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "       Installation Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Installation directory: $InstallDir" -ForegroundColor White
Write-Host ""
Write-Host "To run the agent manually:" -ForegroundColor Yellow
Write-Host "  cd $InstallDir" -ForegroundColor White
Write-Host "  .\run-agent.bat" -ForegroundColor White
Write-Host ""
Write-Host "Or run directly:" -ForegroundColor Yellow
Write-Host "  node agent.js --server $ServerUrl --secret $ClientSecret" -ForegroundColor White
Write-Host ""

# Start the agent
$startNow = Read-Host "Start agent now? (Y/n)"
if ($startNow -ne 'n' -and $startNow -ne 'N') {
    Write-Host ""
    Write-Host "[INFO] Starting agent..." -ForegroundColor Yellow
    & node agent.js --server $ServerUrl --secret $ClientSecret --id $ClientId
}
