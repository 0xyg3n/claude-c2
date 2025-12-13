#!/data/data/com.termux/files/usr/bin/bash
# MCP Remote Agent - Termux (Android)
# Usage: curl -s https://${DOMAIN}/agent/termux | bash
# Or: ./termux.sh -s "ws://your-server:3103" -k "your-secret" -i "MYPHONE"
# Requires: pkg install python (includes pip)

SERVER="ws://${DOMAIN}:3103"
SECRET="AGENT_SECRET_PLACEHOLDER"
ID="${HOSTNAME:-TERMUX-$(getprop ro.product.model 2>/dev/null | tr ' ' '-' || echo 'DEVICE')}"

# Parse arguments
while getopts "s:k:i:" opt; do
    case $opt in
        s) SERVER="$OPTARG" ;;
        k) SECRET="$OPTARG" ;;
        i) ID="$OPTARG" ;;
    esac
done

# Install dependencies if needed
if ! command -v python &> /dev/null; then
    echo "Installing Python..."
    pkg install python -y
fi

python -c "import websockets" 2>/dev/null || {
    echo "Installing websockets..."
    pip install websockets
}

export MCP_SERVER="$SERVER"
export MCP_SECRET="$SECRET"
export MCP_ID="$ID"

python << 'PYEOF'
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
ID = os.environ.get('MCP_ID', 'TERMUX-PHONE')

print(f"\n  \033[36mMCP REMOTE AGENT - Termux/Android\033[0m")
print(f"  ==================================\n")

def get_device_info():
    """Get Android device information"""
    info = {}
    try:
        info['model'] = subprocess.run(['getprop', 'ro.product.model'], capture_output=True, text=True).stdout.strip()
        info['android_version'] = subprocess.run(['getprop', 'ro.build.version.release'], capture_output=True, text=True).stdout.strip()
        info['sdk'] = subprocess.run(['getprop', 'ro.build.version.sdk'], capture_output=True, text=True).stdout.strip()
    except:
        pass
    return info

def run_command(cmd, args):
    try:
        if cmd == 'shell':
            result = subprocess.run(args.get('cmd', ''), shell=True, capture_output=True, text=True, timeout=60)
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
            device = get_device_info()
            return {
                'success': True,
                'hostname': socket.gethostname(),
                'platform': 'Android/Termux',
                'arch': platform.machine(),
                'version': device.get('android_version', platform.release()),
                'model': device.get('model', 'Unknown'),
                'sdk': device.get('sdk', 'Unknown'),
                'user': os.environ.get('USER', 'termux')
            }

        elif cmd == 'process_list':
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')[1:51]
            processes = []
            for line in lines:
                parts = line.split(None, 10)
                if len(parts) >= 2:
                    processes.append({'name': parts[-1][:50] if len(parts) > 2 else parts[0], 'pid': int(parts[1]) if len(parts) > 1 else 0})
            return {'success': True, 'processes': processes}

        elif cmd == 'open_url':
            # Open URL using Android's am command
            url = args.get('url', '')
            result = subprocess.run(
                ['am', 'start', '-a', 'android.intent.action.VIEW', '-d', url],
                capture_output=True, text=True
            )
            return {'success': True, 'stdout': result.stdout, 'stderr': result.stderr}

        elif cmd == 'open_app':
            # Open app by package name
            package = args.get('package', '')
            result = subprocess.run(
                ['am', 'start', '-n', package],
                capture_output=True, text=True
            )
            return {'success': True, 'stdout': result.stdout, 'stderr': result.stderr}

        elif cmd == 'vibrate':
            # Vibrate (requires Termux:API)
            duration = args.get('duration', 500)
            result = subprocess.run(['termux-vibrate', '-d', str(duration)], capture_output=True, text=True)
            return {'success': True}

        elif cmd == 'toast':
            # Show toast message (requires Termux:API)
            msg = args.get('message', 'Hello')
            result = subprocess.run(['termux-toast', msg], capture_output=True, text=True)
            return {'success': True}

        elif cmd == 'notification':
            # Show notification (requires Termux:API)
            title = args.get('title', 'MCP Agent')
            msg = args.get('message', '')
            result = subprocess.run(
                ['termux-notification', '-t', title, '-c', msg],
                capture_output=True, text=True
            )
            return {'success': True}

        elif cmd == 'tts':
            # Text to speech (requires Termux:API)
            text = args.get('text', '')
            result = subprocess.run(['termux-tts-speak', text], capture_output=True, text=True)
            return {'success': True}

        elif cmd == 'clipboard_get':
            # Get clipboard (requires Termux:API)
            result = subprocess.run(['termux-clipboard-get'], capture_output=True, text=True)
            return {'success': True, 'content': result.stdout}

        elif cmd == 'clipboard_set':
            # Set clipboard (requires Termux:API)
            text = args.get('text', '')
            result = subprocess.run(['termux-clipboard-set', text], capture_output=True, text=True)
            return {'success': True}

        elif cmd == 'location':
            # Get location (requires Termux:API)
            result = subprocess.run(['termux-location'], capture_output=True, text=True)
            return {'success': True, 'location': result.stdout}

        elif cmd == 'battery':
            # Get battery status (requires Termux:API)
            result = subprocess.run(['termux-battery-status'], capture_output=True, text=True)
            try:
                return {'success': True, 'battery': json.loads(result.stdout)}
            except:
                return {'success': True, 'battery': result.stdout}

        elif cmd == 'wifi_info':
            # Get WiFi info (requires Termux:API)
            result = subprocess.run(['termux-wifi-connectioninfo'], capture_output=True, text=True)
            try:
                return {'success': True, 'wifi': json.loads(result.stdout)}
            except:
                return {'success': True, 'wifi': result.stdout}

        elif cmd == 'camera_photo':
            # Take photo (requires Termux:API)
            path = args.get('path', '/data/data/com.termux/files/home/photo.jpg')
            camera = args.get('camera', '0')  # 0=back, 1=front
            result = subprocess.run(
                ['termux-camera-photo', '-c', camera, path],
                capture_output=True, text=True, timeout=30
            )
            return {'success': True, 'path': path}

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
            print(f'  [\033[36mINFO\033[0m] Connecting to {SERVER}...')
            async with websockets.connect(SERVER) as ws:
                print(f'  [\033[32mOK\033[0m] Connected!')

                reg = {
                    'type': 'register',
                    'clientId': ID,
                    'authSecret': SECRET,
                    'hostname': socket.gethostname(),
                    'platform': 'Android/Termux',
                    'arch': platform.machine(),
                    'username': os.environ.get('USER', 'termux')
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
