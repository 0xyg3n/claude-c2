#!/bin/bash
# MCP Remote Agent - macOS
# Usage: curl -s https://${DOMAIN}/agent/macos | bash
# Or: ./macos.sh -s "ws://your-server:3103" -k "your-secret" -i "MYMAC"
# Requires: python3 with websockets (pip3 install websockets)

SERVER="ws://${DOMAIN}:3103"
SECRET="AGENT_SECRET_PLACEHOLDER"
ID="${HOSTNAME:-$(hostname -s)}"

# Parse arguments
while getopts "s:k:i:" opt; do
    case $opt in
        s) SERVER="$OPTARG" ;;
        k) SECRET="$OPTARG" ;;
        i) ID="$OPTARG" ;;
    esac
done

# Check for python3
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 required"
    echo "Install: brew install python3 && pip3 install websockets"
    exit 1
fi

# Check websockets module
python3 -c "import websockets" 2>/dev/null || {
    echo "Installing websockets..."
    pip3 install websockets
}

export MCP_SERVER="$SERVER"
export MCP_SECRET="$SECRET"
export MCP_ID="$ID"

python3 << 'PYEOF'
import asyncio
import websockets
import json
import subprocess
import os
import sys
import socket
import platform
import base64
import tempfile

SERVER = os.environ.get('MCP_SERVER', 'ws://${DOMAIN}:3103')
SECRET = os.environ.get('MCP_SECRET', 'AGENT_SECRET_PLACEHOLDER')
ID = os.environ.get('MCP_ID', socket.gethostname())

print(f"\n  \033[36mMCP REMOTE AGENT - macOS\033[0m")
print(f"  ========================\n")

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
                try:
                    files.append({
                        'name': name,
                        'type': 'dir' if os.path.isdir(full) else 'file',
                        'size': os.path.getsize(full) if os.path.isfile(full) else 0
                    })
                except:
                    pass
            return {'success': True, 'files': files}

        elif cmd == 'system_info':
            return {
                'success': True,
                'hostname': socket.gethostname(),
                'platform': 'macOS',
                'arch': platform.machine(),
                'version': platform.mac_ver()[0],
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

        elif cmd == 'screenshot':
            # macOS screencapture command
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
                temp_path = f.name
            try:
                subprocess.run(['screencapture', '-x', temp_path], check=True, timeout=10)
                with open(temp_path, 'rb') as f:
                    b64 = base64.b64encode(f.read()).decode()
                os.unlink(temp_path)
                return {'success': True, 'base64': b64}
            except Exception as e:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                return {'success': False, 'error': str(e)}

        elif cmd == 'download':
            import urllib.request
            urllib.request.urlretrieve(args['url'], args['path'])
            return {'success': True, 'path': args['path']}

        elif cmd == 'open_app':
            subprocess.run(['open', '-a', args['app']], check=True)
            return {'success': True, 'app': args['app']}

        elif cmd == 'open_url':
            subprocess.run(['open', args['url']], check=True)
            return {'success': True, 'url': args['url']}

        elif cmd == 'notify':
            title = args.get('title', 'MCP Agent')
            msg = args.get('message', '')
            subprocess.run([
                'osascript', '-e',
                f'display notification "{msg}" with title "{title}"'
            ], check=True)
            return {'success': True}

        elif cmd == 'status':
            return {'success': True, 'id': ID, 'host': socket.gethostname()}

        else:
            return {'success': False, 'error': f'Unknown command: {cmd}'}

    except Exception as e:
        return {'success': False, 'error': str(e)}

async def main():
    while True:
        try:
            print(f'  [\033[36mINFO\033[0m] Connecting to {SERVER}...')
            async with websockets.connect(SERVER) as ws:
                print(f'  [\033[32mOK\033[0m] Connected!')

                reg = {
                    'type': 'register',
                    'clientId': ID,
                    'authSecret': SECRET,
                    'hostname': socket.gethostname(),
                    'platform': 'macOS',
                    'arch': platform.machine(),
                    'username': os.environ.get('USER', 'unknown')
                }
                await ws.send(json.dumps(reg))

                async for message in ws:
                    msg = json.loads(message)

                    if msg['type'] == 'registered':
                        print(f"  [\033[32mOK\033[0m] Registered as: {msg['clientId']}")
                    elif msg['type'] == 'ping':
                        await ws.send(json.dumps({'type': 'pong'}))
                    elif msg['type'] == 'command':
                        print(f"  [\033[35mCMD\033[0m] {msg['command']}")
                        result = run_command(msg['command'], msg.get('args', {}))
                        resp = {
                            'type': 'command_response',
                            'commandId': msg['commandId'],
                            'result': result
                        }
                        await ws.send(json.dumps(resp))
                        status = '\033[32mOK\033[0m' if result.get('success') else '\033[31mFAIL\033[0m'
                        print(f"  [{status}] Command completed")

        except Exception as e:
            print(f'  [\033[31mERR\033[0m] {e}')

        print('  [\033[33mWARN\033[0m] Reconnecting in 5 seconds...')
        await asyncio.sleep(5)

asyncio.run(main())
PYEOF
