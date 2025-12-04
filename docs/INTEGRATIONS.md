# MCP Remote Agent - Integration Guide

This document covers all integration options for MCP Remote Agent.

## Table of Contents
- [Claude.ai Integration](#claudeai-integration)
- [Claude Code (CLI) Integration](#claude-code-cli-integration)
- [Custom MCP Client Integration](#custom-mcp-client-integration)
- [REST API Integration](#rest-api-integration)
- [WebSocket Direct Integration](#websocket-direct-integration)

---

## Claude.ai Integration

Claude.ai supports external MCP connectors, allowing you to control your C2 infrastructure directly through the Claude.ai web interface.

### Prerequisites
- A deployed MCP Remote Agent server with HTTPS
- Valid SSL certificate (Let's Encrypt or self-signed)
- OAuth credentials (generated during installation)

### Step-by-Step Setup

#### 1. Access Claude.ai Settings

1. Log in to [Claude.ai](https://claude.ai)
2. Click on your profile icon (bottom left)
3. Select **Settings**
4. Navigate to **Integrations** or **MCP Connectors**

#### 2. Add Custom Connector

Click **Add Connector** or **Add Custom MCP Server** and enter:

| Field | Value | Description |
|-------|-------|-------------|
| **Name** | `MCP Remote Agent` | Display name |
| **Server URL** | `https://YOUR_DOMAIN/mcp/sse` | MCP SSE endpoint |
| **Auth Type** | `OAuth 2.0` | Authentication method |
| **OAuth Client ID** | (from installation) | OAuth identifier |
| **OAuth Client Secret** | (from installation) | OAuth secret |
| **Authorization URL** | `https://YOUR_DOMAIN/oauth/authorize` | OAuth auth endpoint |
| **Token URL** | `https://YOUR_DOMAIN/oauth/token` | OAuth token endpoint |

#### 3. Test Connection

1. Click **Connect** or **Authorize**
2. You'll be redirected to authorize the connection
3. After authorization, Claude.ai will connect to your server

#### 4. Verify Tools

Once connected, Claude will have access to all C2 tools. Test with:
```
"List all connected clients"
```

### Configuration Screenshot

```
┌─────────────────────────────────────────────────────────────┐
│ Add MCP Connector                                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Name:           [MCP Remote Agent                    ]      │
│                                                             │
│ Server URL:     [https://c2.example.com/mcp/sse     ]      │
│                                                             │
│ Authentication: (●) OAuth 2.0  ( ) API Key  ( ) None       │
│                                                             │
│ OAuth Client ID:     [abc123...                      ]      │
│ OAuth Client Secret: [xyz789...                      ]      │
│                                                             │
│ Authorization URL:   [https://c2.example.com/oauth/authorize]│
│ Token URL:           [https://c2.example.com/oauth/token    ]│
│                                                             │
│                              [ Cancel ]  [ Connect ]        │
└─────────────────────────────────────────────────────────────┘
```

### Troubleshooting Claude.ai Connection

#### "Connection Failed"
- Verify server is running: `systemctl status claude-c2`
- Check SSL certificate: `curl -v https://YOUR_DOMAIN/health`
- Verify OAuth credentials match `.env` file

#### "Authentication Error"
- Regenerate OAuth credentials in `.env`
- Restart server: `systemctl restart claude-c2`
- Try reconnecting in Claude.ai

#### "Tools Not Loading"
- Check MCP endpoint: `curl https://YOUR_DOMAIN/mcp/sse`
- Verify nginx is proxying correctly
- Check server logs: `journalctl -u claude-c2 -f`

---

## Claude Code (CLI) Integration

Claude Code can connect to MCP servers via configuration.

### Configuration

Add to your Claude Code MCP settings (`~/.claude/mcp_settings.json`):

```json
{
  "mcpServers": {
    "claude-c2": {
      "command": "curl",
      "args": ["-N", "https://YOUR_DOMAIN/mcp/sse"],
      "env": {}
    }
  }
}
```

Or for authenticated access:

```json
{
  "mcpServers": {
    "claude-c2": {
      "url": "https://YOUR_DOMAIN/mcp/sse",
      "transport": "sse",
      "auth": {
        "type": "oauth2",
        "clientId": "YOUR_OAUTH_CLIENT_ID",
        "clientSecret": "YOUR_OAUTH_CLIENT_SECRET",
        "authorizationUrl": "https://YOUR_DOMAIN/oauth/authorize",
        "tokenUrl": "https://YOUR_DOMAIN/oauth/token"
      }
    }
  }
}
```

### Usage

Once configured, Claude Code will have access to all C2 tools:

```bash
$ claude

Claude: I can see you have MCP Remote Agent connected.
I can help you manage remote clients. What would you like to do?

You: List connected clients

Claude: [Uses list_clients tool]
Currently connected clients:
- LAPTOP01 (Windows 11, user: admin)
- WORKSTATION (Windows 10, user: jsmith)
```

---

## Custom MCP Client Integration

Build your own MCP client to interact with the C2 server.

### MCP Protocol Overview

MCP uses JSON-RPC 2.0 over SSE (Server-Sent Events) or WebSocket.

### Python Example

```python
import requests
import json

class MCPClient:
    def __init__(self, server_url, oauth_token):
        self.server_url = server_url
        self.token = oauth_token
        self.session_id = None

    def call_tool(self, tool_name, arguments={}):
        """Call an MCP tool"""
        response = requests.post(
            f"{self.server_url}/mcp/sse",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                }
            },
            headers={"Authorization": f"Bearer {self.token}"}
        )
        return response.json()

    def list_tools(self):
        """Get available tools"""
        response = requests.post(
            f"{self.server_url}/mcp/sse",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list"
            }
        )
        return response.json()

# Usage
client = MCPClient("https://c2.example.com", "your_token")

# List clients
result = client.call_tool("list_clients")
print(result)

# Execute command
result = client.call_tool("shell", {
    "client_id": "LAPTOP01",
    "cmd": "whoami"
})
print(result)
```

### Node.js Example

```javascript
const axios = require('axios');

class MCPClient {
    constructor(serverUrl) {
        this.serverUrl = serverUrl;
    }

    async callTool(toolName, args = {}) {
        const response = await axios.post(`${this.serverUrl}/mcp/sse`, {
            jsonrpc: "2.0",
            id: 1,
            method: "tools/call",
            params: {
                name: toolName,
                arguments: args
            }
        });
        return response.data;
    }
}

// Usage
const client = new MCPClient('https://c2.example.com');

// List clients
const clients = await client.callTool('list_clients');
console.log(clients);

// Take screenshot
const screenshot = await client.callTool('screenshot', {
    client_id: 'LAPTOP01'
});
console.log(screenshot);
```

---

## REST API Integration

The server exposes REST endpoints for direct integration.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health check |
| GET | `/test/clients` | List connected clients |
| POST | `/test/command` | Send command to client |
| GET | `/agents` | Agent download page |
| GET | `/agent/{platform}` | Download agent |

### Examples

#### List Clients
```bash
curl https://YOUR_DOMAIN/test/clients
```

Response:
```json
[
  {
    "id": "LAPTOP01",
    "info": {
      "hostname": "LAPTOP01",
      "platform": "Windows",
      "arch": "AMD64",
      "username": "admin"
    },
    "status": "online"
  }
]
```

#### Send Command
```bash
curl -X POST https://YOUR_DOMAIN/test/command \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "LAPTOP01",
    "command": "shell",
    "args": {"cmd": "whoami"}
  }'
```

Response:
```json
{
  "success": true,
  "result": {
    "success": true,
    "stdout": "laptop01\\admin\n",
    "stderr": "",
    "exitCode": 0
  }
}
```

---

## WebSocket Direct Integration

Connect directly to the WebSocket server for real-time communication.

### Connection

```javascript
const WebSocket = require('ws');

const ws = new WebSocket('wss://YOUR_DOMAIN:3102');

ws.on('open', () => {
    // Register as operator
    ws.send(JSON.stringify({
        type: 'register_operator',
        authSecret: 'YOUR_CLIENT_AUTH_SECRET'
    }));
});

ws.on('message', (data) => {
    const msg = JSON.parse(data);
    console.log('Received:', msg);
});
```

### Message Types

#### Client Registration
```json
{
    "type": "register",
    "clientId": "LAPTOP01",
    "authSecret": "...",
    "hostname": "LAPTOP01",
    "platform": "Windows",
    "arch": "AMD64",
    "username": "admin"
}
```

#### Command
```json
{
    "type": "command",
    "commandId": "uuid",
    "command": "shell",
    "args": {"cmd": "whoami"}
}
```

#### Command Response
```json
{
    "type": "command_response",
    "commandId": "uuid",
    "result": {
        "success": true,
        "stdout": "admin",
        "exitCode": 0
    }
}
```

---

## Security Best Practices

### For Production Use

1. **Use Strong Secrets**
   ```bash
   # Regenerate secrets
   openssl rand -hex 32 > /opt/claude-c2/secrets/oauth.key
   ```

2. **Enable Rate Limiting**
   Add to nginx:
   ```nginx
   limit_req_zone $binary_remote_addr zone=mcp:10m rate=10r/s;
   ```

3. **IP Whitelisting**
   ```nginx
   allow 10.0.0.0/8;
   deny all;
   ```

4. **Log Monitoring**
   ```bash
   # Setup log rotation
   cat > /etc/logrotate.d/claude-c2 << EOF
   /opt/claude-c2/logs/*.log {
       daily
       rotate 14
       compress
       notifempty
   }
   EOF
   ```

---

## Support

For issues and feature requests, please open a GitHub issue.
