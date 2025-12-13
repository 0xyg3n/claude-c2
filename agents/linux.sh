#!/bin/bash
# MCP Remote Agent - Linux
# Usage: curl -s https://${DOMAIN}/agent/linux | bash
# Or: ./linux.sh -s "ws://your-server:3103" -k "your-secret" -i "MYPC"
# Requires: websocat (cargo install websocat) or python3 with websockets

SERVER="ws://${DOMAIN}:3103"
SECRET="AGENT_SECRET_PLACEHOLDER"
ID="${HOSTNAME:-$(hostname)}"

# Parse arguments
while getopts "s:k:i:" opt; do
    case $opt in
        s) SERVER="$OPTARG" ;;
        k) SECRET="$OPTARG" ;;
        i) ID="$OPTARG" ;;
    esac
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log() {
    local type="$1"
    local msg="$2"
    local time=$(date '+%H:%M:%S')
    local color=$NC
    case $type in
        INFO) color=$CYAN ;;
        OK) color=$GREEN ;;
        WARN) color=$YELLOW ;;
        ERR) color=$RED ;;
        CMD) color=$MAGENTA ;;
    esac
    echo -e "  [${time}] ${color}[${type}]${NC} ${msg}"
}

banner() {
    clear
    echo ""
    echo -e "  ${CYAN}MCP REMOTE AGENT - Linux${NC}"
    echo -e "  ${NC}========================${NC}"
    echo ""
}

# Check for websocat or python
if command -v websocat &> /dev/null; then
    WS_CLIENT="websocat"
elif command -v python3 &> /dev/null; then
    WS_CLIENT="python3"
else
    echo "Error: websocat or python3 required"
    echo "Install: cargo install websocat"
    echo "    or : apt install python3 python3-pip && pip3 install websockets"
    exit 1
fi

# Python WebSocket client
run_python_client() {
    python3 << 'PYEOF'
import asyncio
import websockets
import json
import subprocess
import os
import sys
import socket
import platform

SERVER = os.environ.get('MCP_SERVER', 'ws://${DOMAIN}:3103')
SECRET = os.environ.get('MCP_SECRET', 'AGENT_SECRET_PLACEHOLDER')
ID = os.environ.get('MCP_ID', socket.gethostname())

def run_command(cmd, args):
    try:
        if cmd == 'shell':
            result = subprocess.run(args.get('cmd', ''), shell=True, capture_output=True, text=True, timeout=30)
            return {'success': True, 'stdout': result.stdout, 'stderr': result.stderr, 'exitCode': result.returncode}
        elif cmd == 'file_read':
            with open(args['path'], 'r') as f:
                return {'success': True, 'content': f.read()}
        elif cmd == 'file_write':
            with open(args['path'], 'w') as f:
                f.write(args['content'])
            return {'success': True}
        elif cmd == 'file_list':
            path = args.get('path', '.')
            files = []
            for name in os.listdir(path):
                full = os.path.join(path, name)
                files.append({
                    'name': name,
                    'type': 'dir' if os.path.isdir(full) else 'file',
                    'size': os.path.getsize(full) if os.path.isfile(full) else 0
                })
            return {'success': True, 'files': files}
        elif cmd == 'system_info':
            return {
                'success': True,
                'hostname': socket.gethostname(),
                'platform': platform.system(),
                'arch': platform.machine(),
                'version': platform.release(),
                'user': os.environ.get('USER', 'unknown')
            }
        elif cmd == 'process_list':
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')[1:51]
            processes = []
            for line in lines:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    processes.append({'name': parts[10][:50], 'pid': int(parts[1]), 'mem': int(float(parts[3])*1000)})
            return {'success': True, 'processes': processes}
        elif cmd == 'download':
            import urllib.request
            urllib.request.urlretrieve(args['url'], args['path'])
            return {'success': True, 'path': args['path']}
        elif cmd == 'status':
            return {'success': True, 'id': ID, 'host': socket.gethostname()}
        else:
            return {'success': False, 'error': f'Unknown command: {cmd}'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

async def main():
    while True:
        try:
            print(f'  Connecting to {SERVER}...')
            async with websockets.connect(SERVER, ssl=True if SERVER.startswith('wss') else None) as ws:
                print(f'  Connected!')

                # Register
                reg = {
                    'type': 'register',
                    'clientId': ID,
                    'authSecret': SECRET,
                    'hostname': socket.gethostname(),
                    'platform': platform.system(),
                    'arch': platform.machine(),
                    'username': os.environ.get('USER', 'unknown')
                }
                await ws.send(json.dumps(reg))

                async for message in ws:
                    msg = json.loads(message)

                    if msg['type'] == 'registered':
                        print(f"  Registered as: {msg['clientId']}")
                    elif msg['type'] == 'ping':
                        await ws.send(json.dumps({'type': 'pong'}))
                    elif msg['type'] == 'command':
                        print(f"  Command: {msg['command']}")
                        result = run_command(msg['command'], msg.get('args', {}))
                        resp = {
                            'type': 'command_response',
                            'commandId': msg['commandId'],
                            'result': result
                        }
                        await ws.send(json.dumps(resp))
                        print(f"  Result: {'OK' if result.get('success') else 'FAILED'}")

        except Exception as e:
            print(f'  Error: {e}')

        print('  Reconnecting in 5 seconds...')
        await asyncio.sleep(5)

asyncio.run(main())
PYEOF
}

banner
log "INFO" "Agent ID: $ID"
log "INFO" "Server: $SERVER"
log "INFO" "Client: $WS_CLIENT"
echo ""

export MCP_SERVER="$SERVER"
export MCP_SECRET="$SECRET"
export MCP_ID="$ID"

if [ "$WS_CLIENT" = "python3" ]; then
    run_python_client
else
    # websocat-based client (simpler but less features)
    log "INFO" "Using websocat client"
    while true; do
        log "INFO" "Connecting..."
        echo "{\"type\":\"register\",\"clientId\":\"$ID\",\"authSecret\":\"$SECRET\",\"hostname\":\"$(hostname)\",\"platform\":\"Linux\",\"arch\":\"$(uname -m)\",\"username\":\"$USER\"}" | \
        websocat -t "$SERVER" | while read -r line; do
            type=$(echo "$line" | jq -r '.type')
            case "$type" in
                registered)
                    log "OK" "Registered!"
                    ;;
                ping)
                    echo '{"type":"pong"}'
                    ;;
                command)
                    cmd=$(echo "$line" | jq -r '.command')
                    cmdId=$(echo "$line" | jq -r '.commandId')
                    log "CMD" "Command: $cmd"
                    # Execute and respond
                    ;;
            esac
        done
        log "WARN" "Reconnecting in 5 seconds..."
        sleep 5
    done
fi
