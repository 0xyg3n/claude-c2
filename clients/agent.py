#!/usr/bin/env python3
"""
Remote Agent Client (Python)

This script runs on remote PCs to connect to the MCP Remote Agent Controller.
It receives commands from Claude and executes them locally.

Usage:
    python agent.py --server wss://your-server.com:3101 --secret YOUR_CLIENT_SECRET

Environment variables (alternative to command line):
    MCP_SERVER_URL=wss://your-server.com:3101
    MCP_CLIENT_SECRET=your-secret
    MCP_CLIENT_ID=custom-client-id (optional)

Requirements:
    pip install websockets
"""

import asyncio
import json
import os
import platform
import socket
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
import argparse

try:
    import websockets
except ImportError:
    print("Error: websockets package not installed. Run: pip install websockets")
    sys.exit(1)


class Config:
    def __init__(self):
        self.server_url = os.environ.get('MCP_SERVER_URL', 'ws://localhost:3101')
        self.client_secret = os.environ.get('MCP_CLIENT_SECRET', 'client-secret-change-me')
        self.client_id = os.environ.get('MCP_CLIENT_ID', f"{socket.gethostname()}-{os.getpid()}")
        self.reconnect_interval = 5
        self.heartbeat_interval = 30


config = Config()


# =============================================
# Command Handlers
# =============================================

async def handle_shell(args: dict) -> dict:
    """Execute shell command"""
    cmd = args.get('cmd')
    cwd = args.get('cwd', os.getcwd())
    timeout = args.get('timeout', 30)

    if not cmd:
        raise ValueError("No command specified")

    print(f"[Agent] Executing shell command: {cmd}")

    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout
        )
        return {
            'success': process.returncode == 0,
            'stdout': stdout.decode('utf-8', errors='replace').strip(),
            'stderr': stderr.decode('utf-8', errors='replace').strip(),
            'exitCode': process.returncode
        }
    except asyncio.TimeoutError:
        return {
            'success': False,
            'stdout': '',
            'stderr': f'Command timed out after {timeout}s',
            'exitCode': -1
        }
    except Exception as e:
        return {
            'success': False,
            'stdout': '',
            'stderr': str(e),
            'exitCode': 1
        }


async def handle_file_read(args: dict) -> dict:
    """Read file contents"""
    file_path = args.get('path')
    encoding = args.get('encoding', 'utf-8')

    if not file_path:
        raise ValueError("No file path specified")

    print(f"[Agent] Reading file: {file_path}")

    path = Path(file_path)
    content = path.read_text(encoding=encoding)
    stats = path.stat()

    return {
        'success': True,
        'path': str(file_path),
        'content': content,
        'size': stats.st_size,
        'modified': datetime.fromtimestamp(stats.st_mtime).isoformat()
    }


async def handle_file_write(args: dict) -> dict:
    """Write file contents"""
    file_path = args.get('path')
    content = args.get('content')
    encoding = args.get('encoding', 'utf-8')

    if not file_path:
        raise ValueError("No file path specified")
    if content is None:
        raise ValueError("No content specified")

    print(f"[Agent] Writing file: {file_path}")

    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)

    stats = path.stat()
    return {
        'success': True,
        'path': str(file_path),
        'size': stats.st_size,
        'modified': datetime.fromtimestamp(stats.st_mtime).isoformat()
    }


async def handle_file_list(args: dict) -> dict:
    """List directory contents"""
    dir_path = args.get('path', '.')

    print(f"[Agent] Listing directory: {dir_path}")

    path = Path(dir_path)
    files = []

    for entry in path.iterdir():
        try:
            stats = entry.stat()
            files.append({
                'name': entry.name,
                'path': str(entry),
                'type': 'directory' if entry.is_dir() else 'file',
                'size': stats.st_size,
                'modified': datetime.fromtimestamp(stats.st_mtime).isoformat()
            })
        except (OSError, PermissionError):
            files.append({
                'name': entry.name,
                'path': str(entry),
                'type': 'unknown',
                'size': 0,
                'modified': None
            })

    return {
        'success': True,
        'path': str(dir_path),
        'files': files
    }


async def handle_file_delete(args: dict) -> dict:
    """Delete file or directory"""
    target_path = args.get('path')
    recursive = args.get('recursive', False)

    if not target_path:
        raise ValueError("No path specified")

    print(f"[Agent] Deleting: {target_path}")

    path = Path(target_path)
    if path.is_dir():
        if recursive:
            import shutil
            shutil.rmtree(path)
        else:
            path.rmdir()
    else:
        path.unlink()

    return {
        'success': True,
        'path': str(target_path),
        'deleted': True
    }


async def handle_system_info(args: dict) -> dict:
    """Get system information"""
    print("[Agent] Getting system info")

    import psutil

    try:
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return {
            'success': True,
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'arch': platform.machine(),
            'release': platform.release(),
            'version': platform.version(),
            'python_version': platform.python_version(),
            'uptime': None,  # Would need psutil.boot_time()
            'cpu_count': os.cpu_count(),
            'totalmem': memory.total,
            'freemem': memory.available,
            'disk_total': disk.total,
            'disk_free': disk.free,
            'username': os.environ.get('USER', os.environ.get('USERNAME', 'unknown')),
            'homedir': str(Path.home()),
            'cwd': os.getcwd()
        }
    except ImportError:
        # psutil not installed, return basic info
        return {
            'success': True,
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'arch': platform.machine(),
            'release': platform.release(),
            'version': platform.version(),
            'python_version': platform.python_version(),
            'cpu_count': os.cpu_count(),
            'username': os.environ.get('USER', os.environ.get('USERNAME', 'unknown')),
            'homedir': str(Path.home()),
            'cwd': os.getcwd()
        }


async def handle_process_list(args: dict) -> dict:
    """Get running processes"""
    print("[Agent] Listing processes")

    if platform.system() == 'Windows':
        cmd = 'tasklist /fo csv /nh'
    else:
        cmd = 'ps aux --no-headers'

    result = await handle_shell({'cmd': cmd, 'timeout': 10})

    if not result['success']:
        return result

    lines = result['stdout'].strip().split('\n')[:100]
    processes = []

    if platform.system() == 'Windows':
        for line in lines:
            parts = line.split(',')
            if len(parts) >= 5:
                processes.append({
                    'name': parts[0].strip('"'),
                    'pid': parts[1].strip('"'),
                    'memory': parts[4].strip('"')
                })
    else:
        for line in lines:
            parts = line.split()
            if len(parts) >= 11:
                processes.append({
                    'user': parts[0],
                    'pid': parts[1],
                    'cpu': parts[2],
                    'mem': parts[3],
                    'command': ' '.join(parts[10:])
                })

    return {
        'success': True,
        'platform': platform.system(),
        'count': len(processes),
        'processes': processes
    }


async def handle_process_kill(args: dict) -> dict:
    """Kill a process"""
    pid = args.get('pid')
    signal_name = args.get('signal', 'SIGTERM')

    if not pid:
        raise ValueError("No PID specified")

    print(f"[Agent] Killing process: {pid}")

    import signal as sig
    signal_num = getattr(sig, signal_name, sig.SIGTERM)
    os.kill(int(pid), signal_num)

    return {
        'success': True,
        'pid': pid,
        'signal': signal_name
    }


async def handle_download(args: dict) -> dict:
    """Download file from URL"""
    url = args.get('url')
    destination = args.get('destination')

    if not url:
        raise ValueError("No URL specified")
    if not destination:
        raise ValueError("No destination specified")

    print(f"[Agent] Downloading: {url} -> {destination}")

    import urllib.request
    urllib.request.urlretrieve(url, destination)

    stats = Path(destination).stat()
    return {
        'success': True,
        'url': url,
        'destination': destination,
        'size': stats.st_size
    }


async def handle_status(args: dict) -> dict:
    """Get current status"""
    try:
        import psutil
        memory = psutil.virtual_memory()
        load = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]

        return {
            'success': True,
            'clientId': config.client_id,
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'freemem': memory.available,
            'totalmem': memory.total,
            'loadavg': list(load),
            'timestamp': datetime.now().isoformat()
        }
    except ImportError:
        return {
            'success': True,
            'clientId': config.client_id,
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'timestamp': datetime.now().isoformat()
        }


# Command handler registry
COMMAND_HANDLERS = {
    'shell': handle_shell,
    'file_read': handle_file_read,
    'file_write': handle_file_write,
    'file_list': handle_file_list,
    'file_delete': handle_file_delete,
    'system_info': handle_system_info,
    'process_list': handle_process_list,
    'process_kill': handle_process_kill,
    'download': handle_download,
    'status': handle_status,
}


# =============================================
# WebSocket Client
# =============================================

class AgentClient:
    def __init__(self):
        self.ws = None
        self.running = True

    async def connect(self):
        while self.running:
            try:
                print(f"[Agent] Connecting to {config.server_url}...")
                async with websockets.connect(config.server_url) as ws:
                    self.ws = ws
                    print("[Agent] Connected to server")
                    await self.register()
                    await self.run()
            except Exception as e:
                print(f"[Agent] Connection error: {e}")

            if self.running:
                print(f"[Agent] Reconnecting in {config.reconnect_interval}s...")
                await asyncio.sleep(config.reconnect_interval)

    async def register(self):
        await self.send({
            'type': 'register',
            'clientId': config.client_id,
            'authSecret': config.client_secret,
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'arch': platform.machine(),
            'username': os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))
        })

    async def run(self):
        heartbeat_task = asyncio.create_task(self.heartbeat_loop())

        try:
            async for message in self.ws:
                try:
                    data = json.loads(message)
                    await self.handle_message(data)
                except json.JSONDecodeError as e:
                    print(f"[Agent] Invalid JSON: {e}")
                except Exception as e:
                    print(f"[Agent] Error handling message: {e}")
        finally:
            heartbeat_task.cancel()

    async def heartbeat_loop(self):
        while True:
            await asyncio.sleep(config.heartbeat_interval)
            try:
                await self.send({'type': 'heartbeat'})
            except Exception:
                break

    async def handle_message(self, message: dict):
        msg_type = message.get('type')

        if msg_type == 'registered':
            print(f"[Agent] Registered as: {message.get('clientId')}")

        elif msg_type == 'command':
            command_id = message.get('commandId')
            command = message.get('command')
            args = message.get('args', {})

            print(f"[Agent] Received command: {command} ({command_id})")

            handler = COMMAND_HANDLERS.get(command)
            if not handler:
                await self.send({
                    'type': 'command_error',
                    'commandId': command_id,
                    'error': f'Unknown command: {command}'
                })
                return

            try:
                result = await handler(args)
                await self.send({
                    'type': 'command_response',
                    'commandId': command_id,
                    'result': result
                })
            except Exception as e:
                await self.send({
                    'type': 'command_error',
                    'commandId': command_id,
                    'error': str(e)
                })

        elif msg_type == 'heartbeat_ack':
            pass

        elif msg_type == 'error':
            print(f"[Agent] Server error: {message.get('message')}")

        else:
            print(f"[Agent] Unknown message type: {msg_type}")

    async def send(self, data: dict):
        if self.ws:
            await self.ws.send(json.dumps(data))

    def stop(self):
        self.running = False


# =============================================
# Main
# =============================================

def main():
    parser = argparse.ArgumentParser(description='MCP Remote Agent Client')
    parser.add_argument('--server', '-s', help='WebSocket server URL')
    parser.add_argument('--secret', '-k', help='Client authentication secret')
    parser.add_argument('--id', '-i', help='Custom client ID')
    args = parser.parse_args()

    if args.server:
        config.server_url = args.server
    if args.secret:
        config.client_secret = args.secret
    if args.id:
        config.client_id = args.id

    print(f"""
╔══════════════════════════════════════════════════╗
║       MCP Remote Agent Client v1.0.0 (Python)    ║
╠══════════════════════════════════════════════════╣
║  Server:    {config.server_url:<36}║
║  Client ID: {config.client_id[:36]:<36}║
║  Hostname:  {socket.gethostname()[:36]:<36}║
╚══════════════════════════════════════════════════╝
""")

    agent = AgentClient()

    try:
        asyncio.run(agent.connect())
    except KeyboardInterrupt:
        print("\n[Agent] Shutting down...")
        agent.stop()


if __name__ == '__main__':
    main()
