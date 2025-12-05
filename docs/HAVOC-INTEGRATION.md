# Havoc C2 Integration

This document describes the integration between Claude C2 (MCP) and Havoc Framework for enhanced penetration testing capabilities.

## Overview

The Havoc integration provides:

- **Process Migration** - Move implant between processes for persistence/evasion
- **Process Injection** - Inject shellcode into remote processes
- **Token Manipulation** - Steal tokens for privilege escalation
- **Native C Implant** - Havoc Demons with advanced evasion (sleep obfuscation, syscalls)
- **Unified Control** - Manage both MCP agents and Havoc Demons from Claude

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         UNIFIED C2 ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌──────────────┐         ┌──────────────────────────────────────┐    │
│   │   Claude AI  │         │          MCP Server                  │    │
│   │              │◄───────►│  (Extended with Havoc Bridge)        │    │
│   │  Operator    │   MCP   │                                      │    │
│   └──────────────┘         └──────────────┬───────────────────────┘    │
│                                           │                              │
│                          ┌────────────────┼────────────────┐            │
│                          │                │                │            │
│                          ▼                ▼                ▼            │
│                   ┌────────────┐   ┌────────────┐   ┌────────────┐     │
│                   │ MCP Agents │   │  Havoc     │   │  Havoc     │     │
│                   │ (Python/   │   │  Bridge    │   │ Teamserver │     │
│                   │  PS/Bash)  │   │            │   │            │     │
│                   └────────────┘   └─────┬──────┘   └──────┬─────┘     │
│                                          │                  │           │
│                                          └──────────────────┘           │
│                                                    │                    │
│                                                    ▼                    │
│                                          ┌─────────────────┐           │
│                                          │  Havoc Demons   │           │
│                                          │  (Native C)     │           │
│                                          │                 │           │
│                                          │ • Process Inject│           │
│                                          │ • Token Steal   │           │
│                                          │ • Sleep Obfusc  │           │
│                                          └─────────────────┘           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Setup

### 1. Install Havoc Framework

```bash
# Clone Havoc (already done at /home/iozac/havoc-mcp)
cd /home/iozac/havoc-mcp

# Build teamserver
cd teamserver
go mod download
go build -o ../havoc-teamserver .

# Build client (optional - we use Claude as operator)
cd ../client
make
```

### 2. Configure Havoc Teamserver

Create `profiles/mcp-profile.yaotl`:

```yaml
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "claude" {
        Password = "claude-operator-password"
    }
}

Service {
    Endpoint = "service"
    Password = "mcp-service-password"
}

Listeners {
    Http {
        Name = "MCP-HTTP"
        Hosts = ["your-c2-domain.com"]
        HostBind = "0.0.0.0"
        PortBind = 443
        PortConn = 443
        Secure = true
    }
}

Demon {
    Sleep = 5
    Jitter = 20

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn86 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
```

### 3. Start Havoc Teamserver

```bash
./havoc-teamserver --profile profiles/mcp-profile.yaotl
```

### 4. Configure MCP Bridge

Add to `.env`:

```env
HAVOC_ENABLED=true
HAVOC_TEAMSERVER=ws://127.0.0.1:40056/service
HAVOC_PASSWORD=mcp-service-password
```

### 5. Restart MCP Server

```bash
sudo systemctl restart mcp-remote-agent.service
```

## MCP Tools for Havoc

### Demon Management

| Tool | Description |
|------|-------------|
| `havoc_demons` | List all connected Havoc Demons |
| `havoc_demon_info` | Get detailed Demon information |

### Execution

| Tool | Description |
|------|-------------|
| `havoc_shell` | Execute cmd.exe command |
| `havoc_powershell` | Execute PowerShell (with optional AMSI bypass) |

### Process Operations

| Tool | Description | MITRE |
|------|-------------|-------|
| `havoc_migrate` | Migrate to another process | T1055 |
| `havoc_inject` | Inject shellcode into process | T1055.001 |
| `havoc_spawn` | Spawn sacrificial process and inject | T1055.012 |

### Token Manipulation

| Tool | Description | MITRE |
|------|-------------|-------|
| `havoc_token_steal` | Steal token from process | T1134.001 |
| `havoc_token_list` | List available tokens | T1134 |

### File Operations

| Tool | Description |
|------|-------------|
| `havoc_download` | Download file from target |
| `havoc_upload` | Upload file to target |

### Surveillance

| Tool | Description |
|------|-------------|
| `havoc_screenshot` | Capture screen |

### Demon Control

| Tool | Description |
|------|-------------|
| `havoc_sleep` | Configure sleep time and jitter |
| `havoc_exit` | Terminate Demon |

### Payload Generation

| Tool | Description |
|------|-------------|
| `havoc_generate` | Generate Demon payload (exe/dll/shellcode) |

## Usage Examples

### Basic Shell Execution

```
Operator: "Run whoami on the Havoc demon"
Claude: [Uses havoc_shell to execute whoami, returns username]
```

### Process Migration

```
Operator: "Migrate to explorer.exe for persistence"
Claude: [Lists processes, finds explorer.exe PID, uses havoc_migrate]
```

### Privilege Escalation via Token Theft

```
Operator: "Escalate to SYSTEM using token theft"
Claude: [Finds SYSTEM process, uses havoc_token_steal, confirms elevated context]
```

### Payload Generation

```
Operator: "Generate a Windows DLL beacon"
Claude: [Uses havoc_generate with format=dll, returns payload]
```

## Comparison: MCP Agents vs Havoc Demons

| Feature | MCP Agents | Havoc Demons |
|---------|------------|--------------|
| **Language** | Python/PowerShell/Bash | Native C |
| **Platforms** | Win/Lin/Mac/Android | Windows (primary) |
| **Process Inject** | No | Yes (multiple methods) |
| **Token Manipulation** | No | Yes |
| **Sleep Obfuscation** | No | Yes (Foliage/Ekko) |
| **Syscall Evasion** | No | Yes (indirect syscalls) |
| **Dependencies** | Python/PS runtime | None (standalone) |
| **Deployment** | One-liner | Staged/Stageless |

## When to Use Each

**Use MCP Agents for:**
- Quick deployment with one-liners
- Cross-platform operations (Linux, macOS, Android)
- Initial access and reconnaissance
- Environments where native implants are detected

**Use Havoc Demons for:**
- Windows targets requiring evasion
- Process migration and injection
- Token manipulation and privilege escalation
- Long-term persistence
- Operations against EDR-protected systems

## Security Considerations

1. **Havoc teamserver** should only be accessible from trusted networks
2. Use strong passwords for service authentication
3. Enable TLS for all communications
4. Regularly rotate credentials
5. Monitor for compromise indicators

## Troubleshooting

### Bridge Not Connecting

```bash
# Check Havoc teamserver is running
netstat -tlnp | grep 40056

# Check service endpoint
curl -v ws://localhost:40056/service
```

### Demon Not Responding

1. Check Demon sleep time (`havoc_sleep` to reduce)
2. Verify network connectivity
3. Check for EDR/AV blocking

### Authentication Failures

1. Verify password hash matches in config
2. Check for IP restrictions on teamserver
3. Review Havoc teamserver logs
