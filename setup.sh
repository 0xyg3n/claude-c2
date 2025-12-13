#!/bin/bash
#
# MCP Remote Agent Controller - Setup Script
# Run with: sudo bash setup.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           MCP Remote Agent Controller Setup                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo bash setup.sh)${NC}"
    exit 1
fi

PROJECT_DIR="/home/iozac/claude-c2"
DOMAIN="${DOMAIN}"

echo -e "${YELLOW}[1/7] Installing systemd service...${NC}"
cp "$PROJECT_DIR/config/claude-c2.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable claude-c2
echo -e "${GREEN}✓ Systemd service installed${NC}"

echo -e "${YELLOW}[2/7] Starting MCP server (required for health checks)...${NC}"
systemctl start claude-c2
sleep 3
if systemctl is-active --quiet claude-c2; then
    echo -e "${GREEN}✓ MCP server is running${NC}"
else
    echo -e "${RED}✗ MCP server failed to start${NC}"
    journalctl -u claude-c2 --no-pager -n 20
    exit 1
fi

echo -e "${YELLOW}[3/7] Installing nginx configuration (HTTP)...${NC}"
cp "$PROJECT_DIR/config/nginx-mcp.conf" /etc/nginx/sites-available/claude-c2
ln -sf /etc/nginx/sites-available/claude-c2 /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
echo -e "${GREEN}✓ Nginx HTTP configuration installed${NC}"

echo -e "${YELLOW}[4/7] Obtaining SSL certificate via certbot...${NC}"
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@localhost --redirect || {
    echo -e "${YELLOW}Certbot automation failed. Running interactive mode...${NC}"
    certbot --nginx -d "$DOMAIN"
}
echo -e "${GREEN}✓ SSL certificate configured${NC}"

echo -e "${YELLOW}[5/7] Setting up WebSocket SSL (port 3102)...${NC}"
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    cp "$PROJECT_DIR/config/nginx-ws.conf" /etc/nginx/sites-available/mcp-ws
    ln -sf /etc/nginx/sites-available/mcp-ws /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx
    echo -e "${GREEN}✓ WebSocket SSL configured on port 3102${NC}"
else
    echo -e "${YELLOW}⚠ SSL cert not found, skipping WebSocket SSL${NC}"
fi

echo -e "${YELLOW}[6/7] Opening firewall port 3102...${NC}"
if command -v ufw &> /dev/null; then
    ufw allow 3102/tcp comment 'MCP WebSocket' 2>/dev/null || true
    echo -e "${GREEN}✓ UFW rule added${NC}"
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=3102/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    echo -e "${GREEN}✓ Firewalld rule added${NC}"
else
    echo -e "${YELLOW}No firewall detected, skipping...${NC}"
fi

echo -e "${YELLOW}[7/7] Verifying setup...${NC}"
sleep 2
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:3100/health" || echo "000")
if [ "$HTTP_STATUS" = "200" ]; then
    echo -e "${GREEN}✓ Server health check passed${NC}"
else
    echo -e "${YELLOW}⚠ Health check returned: $HTTP_STATUS${NC}"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    SETUP COMPLETE!                           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Server URL:${NC} https://$DOMAIN"
echo -e "${BLUE}MCP Endpoint:${NC} https://$DOMAIN/mcp/sse"
echo -e "${BLUE}WebSocket (clients):${NC} wss://$DOMAIN:3102"
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}CREDENTIALS FOR CLAUDE.AI CONNECTOR:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
source "$PROJECT_DIR/config/.env"
echo -e "  ${BLUE}OAuth Client ID:${NC}     $OAUTH_CLIENT_ID"
echo -e "  ${BLUE}OAuth Client Secret:${NC} $OAUTH_CLIENT_SECRET"
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}SECRET FOR REMOTE CLIENTS:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BLUE}Client Auth Secret:${NC}  $CLIENT_AUTH_SECRET"
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}To connect a Windows PC, run in PowerShell:${NC}"
echo "  irm https://$DOMAIN/install.ps1 | iex"
echo ""
echo -e "${BLUE}Or manually:${NC}"
echo "  node agent.js --server wss://$DOMAIN:3102 --secret $CLIENT_AUTH_SECRET"
echo ""
echo -e "${BLUE}To check server status:${NC}"
echo "  systemctl status claude-c2"
echo "  curl https://$DOMAIN/health"
echo ""
