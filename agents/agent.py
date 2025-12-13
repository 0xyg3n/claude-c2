#!/usr/bin/env python3
"""
MCP Remote Agent - Cross-Platform Python Client
Usage: python agent.py --server ws://<SERVER_DOMAIN>:3103 --secret YOUR_SECRET --id MYDEVICE
Requires: pip install websockets
"""

import asyncio
import websockets
import json
import subprocess
import os
import sys
import socket
import platform
import argparse
import base64
import tempfile

# Configuration
DEFAULT_SERVER = "ws://<SERVER_DOMAIN>:3103"
DEFAULT_SECRET = "AGENT_SECRET_PLACEHOLDER"

# Detect platform
PLATFORM = platform.system()
IS_WINDOWS = PLATFORM == "Windows"
IS_MACOS = PLATFORM == "Darwin"
IS_LINUX = PLATFORM == "Linux"
IS_TERMUX = os.path.exists('/data/data/com.termux')

def get_default_id():
    if IS_TERMUX:
        try:
            model = subprocess.run(['getprop', 'ro.product.model'], capture_output=True, text=True).stdout.strip()
            return f"TERMUX-{model.replace(' ', '-')}"
        except:
            pass
    return socket.gethostname()

class MCPAgent:
    def __init__(self, server, secret, client_id):
        self.server = server
        self.secret = secret
        self.client_id = client_id
        self.cmd_count = 0

    def log(self, level, msg):
        colors = {
            'INFO': '\033[36m',
            'OK': '\033[32m',
            'WARN': '\033[33m',
            'ERR': '\033[31m',
            'CMD': '\033[35m'
        }
        reset = '\033[0m'
        color = colors.get(level, '')
        print(f"  [{color}{level}{reset}] {msg}")

    def get_system_info(self):
        info = {
            'success': True,
            'hostname': socket.gethostname(),
            'platform': PLATFORM,
            'arch': platform.machine(),
            'version': platform.release(),
            'user': os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))
        }

        if IS_WINDOWS:
            info['platform'] = 'Windows'
            info['version'] = platform.version()
        elif IS_MACOS:
            info['platform'] = 'macOS'
            info['version'] = platform.mac_ver()[0]
        elif IS_TERMUX:
            info['platform'] = 'Android/Termux'
            try:
                info['android_version'] = subprocess.run(['getprop', 'ro.build.version.release'],
                    capture_output=True, text=True).stdout.strip()
                info['model'] = subprocess.run(['getprop', 'ro.product.model'],
                    capture_output=True, text=True).stdout.strip()
            except:
                pass

        return info

    def take_screenshot(self):
        """Platform-specific screenshot"""
        try:
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
                temp_path = f.name

            if IS_WINDOWS:
                # Use PowerShell for Windows screenshot
                ps_script = f'''
                Add-Type -AssemblyName System.Windows.Forms
                $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
                $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
                $bitmap.Save("{temp_path}")
                '''
                subprocess.run(['powershell', '-Command', ps_script], check=True, timeout=10)
            elif IS_MACOS:
                subprocess.run(['screencapture', '-x', temp_path], check=True, timeout=10)
            elif IS_LINUX and not IS_TERMUX:
                # Try various Linux screenshot tools
                for cmd in [
                    ['gnome-screenshot', '-f', temp_path],
                    ['scrot', temp_path],
                    ['import', '-window', 'root', temp_path]
                ]:
                    try:
                        subprocess.run(cmd, check=True, timeout=10)
                        break
                    except:
                        continue
            else:
                return {'success': False, 'error': 'Screenshot not supported on this platform'}

            with open(temp_path, 'rb') as f:
                b64 = base64.b64encode(f.read()).decode()
            os.unlink(temp_path)
            return {'success': True, 'base64': b64}
        except Exception as e:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            return {'success': False, 'error': str(e)}

    def run_command(self, cmd, args):
        try:
            if cmd == 'shell':
                shell_cmd = args.get('cmd', '')
                if IS_WINDOWS:
                    result = subprocess.run(shell_cmd, shell=True, capture_output=True, text=True, timeout=60)
                else:
                    result = subprocess.run(shell_cmd, shell=True, capture_output=True, text=True, timeout=60)
                return {
                    'success': True,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'exitCode': result.returncode
                }

            elif cmd == 'powershell' and IS_WINDOWS:
                result = subprocess.run(['powershell', '-Command', args.get('cmd', '')],
                    capture_output=True, text=True, timeout=60)
                return {'success': True, 'output': result.stdout, 'error': result.stderr}

            elif cmd == 'file_read':
                with open(args['path'], 'r', encoding='utf-8', errors='ignore') as f:
                    return {'success': True, 'content': f.read()}

            elif cmd == 'file_read_binary':
                with open(args['path'], 'rb') as f:
                    return {'success': True, 'base64': base64.b64encode(f.read()).decode()}

            elif cmd == 'file_write':
                with open(args['path'], 'w') as f:
                    f.write(args['content'])
                return {'success': True}

            elif cmd == 'file_write_binary':
                with open(args['path'], 'wb') as f:
                    f.write(base64.b64decode(args['base64']))
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

            elif cmd == 'file_delete':
                path = args['path']
                if os.path.isdir(path):
                    import shutil
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                return {'success': True}

            elif cmd == 'system_info':
                return self.get_system_info()

            elif cmd == 'process_list':
                if IS_WINDOWS:
                    result = subprocess.run(['tasklist', '/fo', 'csv'], capture_output=True, text=True)
                    lines = result.stdout.strip().split('\n')[1:51]
                    processes = []
                    for line in lines:
                        parts = line.replace('"', '').split(',')
                        if len(parts) >= 2:
                            processes.append({'name': parts[0], 'pid': int(parts[1])})
                else:
                    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                    lines = result.stdout.strip().split('\n')[1:51]
                    processes = []
                    for line in lines:
                        parts = line.split(None, 10)
                        if len(parts) >= 2:
                            processes.append({
                                'name': parts[-1][:50] if len(parts) > 2 else parts[0],
                                'pid': int(parts[1]) if len(parts) > 1 else 0
                            })
                return {'success': True, 'processes': processes}

            elif cmd == 'screenshot':
                return self.take_screenshot()

            elif cmd == 'download':
                import urllib.request
                urllib.request.urlretrieve(args['url'], args['path'])
                return {'success': True, 'path': args['path']}

            elif cmd == 'upload':
                with open(args['path'], 'rb') as f:
                    return {'success': True, 'base64': base64.b64encode(f.read()).decode(), 'filename': os.path.basename(args['path'])}

            elif cmd == 'open_url':
                import webbrowser
                if IS_TERMUX:
                    subprocess.run(['am', 'start', '-a', 'android.intent.action.VIEW', '-d', args['url']])
                else:
                    webbrowser.open(args['url'])
                return {'success': True, 'url': args['url']}

            elif cmd == 'env':
                return {'success': True, 'env': dict(os.environ)}

            elif cmd == 'cwd':
                if 'path' in args:
                    os.chdir(args['path'])
                return {'success': True, 'cwd': os.getcwd()}

            elif cmd == 'status':
                return {'success': True, 'id': self.client_id, 'host': socket.gethostname(), 'commands': self.cmd_count}

            # Platform-specific commands
            elif cmd == 'notify':
                if IS_MACOS:
                    subprocess.run(['osascript', '-e',
                        f'display notification "{args.get("message", "")}" with title "{args.get("title", "MCP Agent")}"'])
                elif IS_TERMUX:
                    subprocess.run(['termux-notification', '-t', args.get('title', 'MCP'), '-c', args.get('message', '')])
                elif IS_LINUX:
                    subprocess.run(['notify-send', args.get('title', 'MCP Agent'), args.get('message', '')])
                elif IS_WINDOWS:
                    # PowerShell toast notification
                    ps = f'''
                    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                    $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
                    $textNodes = $template.GetElementsByTagName("text")
                    $textNodes.Item(0).AppendChild($template.CreateTextNode("{args.get('title', 'MCP Agent')}"))
                    $textNodes.Item(1).AppendChild($template.CreateTextNode("{args.get('message', '')}"))
                    '''
                    subprocess.run(['powershell', '-Command', ps])
                return {'success': True}

            else:
                return {'success': False, 'error': f'Unknown command: {cmd}'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def run(self):
        print(f"\n  \033[36mMCP REMOTE AGENT - {PLATFORM}\033[0m")
        print(f"  {'=' * (22 + len(PLATFORM))}\n")
        self.log('INFO', f"Agent ID: {self.client_id}")
        self.log('INFO', f"Server: {self.server}")
        self.log('INFO', f"Platform: {PLATFORM} {'(Termux)' if IS_TERMUX else ''}")
        print()

        while True:
            try:
                self.log('INFO', 'Connecting...')
                async with websockets.connect(self.server) as ws:
                    self.log('OK', 'Connected!')

                    # Register
                    info = self.get_system_info()
                    reg = {
                        'type': 'register',
                        'clientId': self.client_id,
                        'authSecret': self.secret,
                        'hostname': info['hostname'],
                        'platform': info['platform'],
                        'arch': info['arch'],
                        'username': info['user']
                    }
                    await ws.send(json.dumps(reg))

                    async for message in ws:
                        msg = json.loads(message)

                        if msg['type'] == 'registered':
                            self.log('OK', f"Registered as: {msg['clientId']}")
                        elif msg['type'] == 'ping':
                            await ws.send(json.dumps({'type': 'pong'}))
                        elif msg['type'] == 'command':
                            self.cmd_count += 1
                            self.log('CMD', f"[{self.cmd_count}] {msg['command']}")

                            result = self.run_command(msg['command'], msg.get('args', {}))

                            resp = {
                                'type': 'command_response',
                                'commandId': msg['commandId'],
                                'result': result
                            }
                            await ws.send(json.dumps(resp))

                            if result.get('success'):
                                self.log('OK', 'Command completed')
                            else:
                                self.log('ERR', f"Failed: {result.get('error', 'Unknown error')}")

            except Exception as e:
                self.log('ERR', str(e))

            self.log('WARN', 'Reconnecting in 5 seconds...')
            await asyncio.sleep(5)


def main():
    parser = argparse.ArgumentParser(description='MCP Remote Agent - Cross-Platform Client')
    parser.add_argument('--server', '-s', default=DEFAULT_SERVER, help='WebSocket server URL')
    parser.add_argument('--secret', '-k', default=DEFAULT_SECRET, help='Authentication secret')
    parser.add_argument('--id', '-i', default=get_default_id(), help='Client ID')
    args = parser.parse_args()

    agent = MCPAgent(args.server, args.secret, args.id)
    asyncio.run(agent.run())


if __name__ == '__main__':
    main()
