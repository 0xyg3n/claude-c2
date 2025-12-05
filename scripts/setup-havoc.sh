#!/bin/bash
#
# Havoc C2 + MCP Integration Setup Script
# For authorized penetration testing only
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
HAVOC_DIR="/home/iozac/havoc-mcp"

echo "============================================"
echo "  Havoc C2 + MCP Integration Setup"
echo "============================================"
echo ""

# Check dependencies
check_deps() {
    echo "[*] Checking dependencies..."

    local missing=()

    command -v go >/dev/null 2>&1 || missing+=("golang")
    command -v make >/dev/null 2>&1 || missing+=("make")
    command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || missing+=("mingw-w64")
    command -v nasm >/dev/null 2>&1 || missing+=("nasm")

    if [ ${#missing[@]} -ne 0 ]; then
        echo "[!] Missing dependencies: ${missing[*]}"
        echo "[*] Installing..."
        sudo apt update
        sudo apt install -y golang make mingw-w64 nasm
    fi

    echo "[+] Dependencies OK"
}

# Build Havoc teamserver
build_teamserver() {
    echo ""
    echo "[*] Building Havoc Teamserver..."

    cd "$HAVOC_DIR/teamserver"

    # Download Go modules
    go mod download

    # Build
    go build -o "$HAVOC_DIR/havoc-teamserver" .

    echo "[+] Teamserver built: $HAVOC_DIR/havoc-teamserver"
}

# Build Havoc client (optional)
build_client() {
    echo ""
    echo "[*] Building Havoc Client (optional)..."

    # Check for Qt dependencies
    if ! command -v qmake >/dev/null 2>&1; then
        echo "[!] Qt not installed, skipping client build"
        echo "    Install with: sudo apt install qt5-default qtbase5-dev"
        return
    fi

    cd "$HAVOC_DIR/client"
    make

    echo "[+] Client built"
}

# Create Havoc profile for MCP integration
create_profile() {
    echo ""
    echo "[*] Creating MCP integration profile..."

    local profile_dir="$HAVOC_DIR/profiles"
    mkdir -p "$profile_dir"

    # Generate random passwords
    local service_pass=$(openssl rand -base64 24)
    local operator_pass=$(openssl rand -base64 24)

    cat > "$profile_dir/mcp-integration.yaotl" << EOF
# Havoc C2 Profile for MCP Integration
# Generated: $(date)

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
        Password = "$operator_pass"
    }
}

Service {
    Endpoint = "service"
    Password = "$service_pass"
}

Listeners {
    Http {
        Name = "MCP-HTTPS"
        Hosts = ["$(hostname -I | awk '{print $1}')"]
        HostBind = "0.0.0.0"
        PortBind = 8443
        PortConn = 8443
        Secure = false

        Response {
            Headers = [
                "Content-Type: text/html",
                "Server: Apache/2.4.41"
            ]
        }
    }
}

Demon {
    Sleep = 5
    Jitter = 25

    Injection {
        Spawn64 = "C:\\\\Windows\\\\System32\\\\notepad.exe"
        Spawn86 = "C:\\\\Windows\\\\SysWOW64\\\\notepad.exe"
    }
}
EOF

    echo "[+] Profile created: $profile_dir/mcp-integration.yaotl"
    echo ""
    echo "    Service Password: $service_pass"
    echo "    Operator Password: $operator_pass"
    echo ""

    # Update MCP .env
    if [ -f "$PROJECT_ROOT/.env" ]; then
        echo "" >> "$PROJECT_ROOT/.env"
        echo "# Havoc Integration" >> "$PROJECT_ROOT/.env"
        echo "HAVOC_ENABLED=true" >> "$PROJECT_ROOT/.env"
        echo "HAVOC_TEAMSERVER=ws://127.0.0.1:40056/service" >> "$PROJECT_ROOT/.env"
        echo "HAVOC_PASSWORD=$service_pass" >> "$PROJECT_ROOT/.env"
        echo "[+] Updated .env with Havoc credentials"
    fi
}

# Create systemd service for Havoc
create_service() {
    echo ""
    echo "[*] Creating systemd service..."

    sudo tee /etc/systemd/system/havoc-teamserver.service > /dev/null << EOF
[Unit]
Description=Havoc C2 Teamserver
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HAVOC_DIR
ExecStart=$HAVOC_DIR/havoc-teamserver --profile $HAVOC_DIR/profiles/mcp-integration.yaotl
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    echo "[+] Service created: havoc-teamserver.service"
    echo "    Start with: sudo systemctl start havoc-teamserver"
    echo "    Enable with: sudo systemctl enable havoc-teamserver"
}

# Main
main() {
    check_deps
    build_teamserver
    # build_client  # Uncomment if you want the GUI client
    create_profile
    create_service

    echo ""
    echo "============================================"
    echo "  Setup Complete!"
    echo "============================================"
    echo ""
    echo "Next steps:"
    echo "  1. Start Havoc: sudo systemctl start havoc-teamserver"
    echo "  2. Restart MCP: sudo systemctl restart mcp-remote-agent"
    echo "  3. Generate payload in Claude: 'Generate a Havoc beacon'"
    echo ""
    echo "Havoc tools are now available in Claude:"
    echo "  - havoc_demons     - List Havoc implants"
    echo "  - havoc_shell      - Execute commands"
    echo "  - havoc_migrate    - Process migration"
    echo "  - havoc_inject     - Shellcode injection"
    echo "  - havoc_token_steal - Token manipulation"
    echo ""
}

main "$@"
