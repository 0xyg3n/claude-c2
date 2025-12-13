#!/usr/bin/env node
/**
 * Remote Agent Client
 *
 * This script runs on remote PCs to connect to the MCP Remote Agent Controller.
 * It receives commands from Claude and executes them locally.
 *
 * Usage:
 *   node agent.js --server wss://your-server.com:3101 --secret YOUR_CLIENT_SECRET
 *
 * Environment variables (alternative to command line):
 *   MCP_SERVER_URL=wss://your-server.com:3101
 *   MCP_CLIENT_SECRET=your-secret
 *   MCP_CLIENT_ID=custom-client-id (optional)
 */

import WebSocket from 'ws';
import os from 'os';
import { exec, spawn } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Configuration
const config = {
  serverUrl: process.env.MCP_SERVER_URL || 'ws://localhost:3101',
  clientSecret: process.env.MCP_CLIENT_SECRET || 'client-secret-change-me',
  clientId: process.env.MCP_CLIENT_ID || `${os.hostname()}-${process.pid}`,
  reconnectInterval: 5000,
  heartbeatInterval: 30000,
};

// Parse command line arguments
for (let i = 2; i < process.argv.length; i++) {
  switch (process.argv[i]) {
    case '--server':
    case '-s':
      config.serverUrl = process.argv[++i];
      break;
    case '--secret':
    case '-k':
      config.clientSecret = process.argv[++i];
      break;
    case '--id':
    case '-i':
      config.clientId = process.argv[++i];
      break;
    case '--help':
    case '-h':
      console.log(`
Remote Agent Client

Usage:
  node agent.js [options]

Options:
  --server, -s <url>    WebSocket server URL (default: ws://localhost:3101)
  --secret, -k <secret> Client authentication secret
  --id, -i <id>         Custom client ID (default: hostname-pid)
  --help, -h            Show this help message

Environment Variables:
  MCP_SERVER_URL        WebSocket server URL
  MCP_CLIENT_SECRET     Client authentication secret
  MCP_CLIENT_ID         Custom client ID
      `);
      process.exit(0);
  }
}

// =============================================
// Command Handlers
// =============================================
const commandHandlers = {
  // Execute shell command
  async shell(args) {
    const { cmd, cwd = process.cwd(), timeout = 30000 } = args;
    if (!cmd) throw new Error('No command specified');

    console.log(`[Agent] Executing shell command: ${cmd}`);

    try {
      const { stdout, stderr } = await execAsync(cmd, {
        cwd,
        timeout,
        maxBuffer: 10 * 1024 * 1024, // 10MB
      });
      return {
        success: true,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        exitCode: 0,
      };
    } catch (error) {
      return {
        success: false,
        stdout: error.stdout?.trim() || '',
        stderr: error.stderr?.trim() || error.message,
        exitCode: error.code || 1,
      };
    }
  },

  // Read file contents
  async file_read(args) {
    const { path: filePath, encoding = 'utf8' } = args;
    if (!filePath) throw new Error('No file path specified');

    console.log(`[Agent] Reading file: ${filePath}`);

    const content = await fs.readFile(filePath, encoding);
    const stats = await fs.stat(filePath);

    return {
      success: true,
      path: filePath,
      content,
      size: stats.size,
      modified: stats.mtime.toISOString(),
    };
  },

  // Write file contents
  async file_write(args) {
    const { path: filePath, content, encoding = 'utf8', mode = 0o644 } = args;
    if (!filePath) throw new Error('No file path specified');
    if (content === undefined) throw new Error('No content specified');

    console.log(`[Agent] Writing file: ${filePath}`);

    // Ensure directory exists
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, { encoding, mode });

    const stats = await fs.stat(filePath);
    return {
      success: true,
      path: filePath,
      size: stats.size,
      modified: stats.mtime.toISOString(),
    };
  },

  // List directory contents
  async file_list(args) {
    const { path: dirPath = '.', recursive = false } = args;

    console.log(`[Agent] Listing directory: ${dirPath}`);

    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    const files = [];

    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      const stats = await fs.stat(fullPath).catch(() => null);

      files.push({
        name: entry.name,
        path: fullPath,
        type: entry.isDirectory() ? 'directory' : 'file',
        size: stats?.size || 0,
        modified: stats?.mtime?.toISOString() || null,
      });
    }

    return {
      success: true,
      path: dirPath,
      files,
    };
  },

  // Delete file or directory
  async file_delete(args) {
    const { path: targetPath, recursive = false } = args;
    if (!targetPath) throw new Error('No path specified');

    console.log(`[Agent] Deleting: ${targetPath}`);

    const stats = await fs.stat(targetPath);
    if (stats.isDirectory()) {
      await fs.rm(targetPath, { recursive, force: true });
    } else {
      await fs.unlink(targetPath);
    }

    return {
      success: true,
      path: targetPath,
      deleted: true,
    };
  },

  // Get system information
  async system_info() {
    console.log(`[Agent] Getting system info`);

    return {
      success: true,
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      release: os.release(),
      type: os.type(),
      uptime: os.uptime(),
      loadavg: os.loadavg(),
      totalmem: os.totalmem(),
      freemem: os.freemem(),
      cpus: os.cpus().length,
      networkInterfaces: Object.keys(os.networkInterfaces()),
      homedir: os.homedir(),
      tmpdir: os.tmpdir(),
      username: os.userInfo().username,
    };
  },

  // Get running processes
  async process_list() {
    console.log(`[Agent] Listing processes`);

    const platform = os.platform();
    let cmd;

    if (platform === 'win32') {
      cmd = 'tasklist /fo csv /nh';
    } else {
      cmd = 'ps aux --no-headers';
    }

    const { stdout } = await execAsync(cmd, { maxBuffer: 10 * 1024 * 1024 });
    const lines = stdout.trim().split('\n');

    const processes = lines.slice(0, 100).map(line => {
      if (platform === 'win32') {
        const parts = line.split(',').map(p => p.replace(/"/g, ''));
        return { name: parts[0], pid: parts[1], memory: parts[4] };
      } else {
        const parts = line.trim().split(/\s+/);
        return {
          user: parts[0],
          pid: parts[1],
          cpu: parts[2],
          mem: parts[3],
          command: parts.slice(10).join(' '),
        };
      }
    });

    return {
      success: true,
      platform,
      count: processes.length,
      processes,
    };
  },

  // Kill a process
  async process_kill(args) {
    const { pid, signal = 'SIGTERM' } = args;
    if (!pid) throw new Error('No PID specified');

    console.log(`[Agent] Killing process: ${pid}`);

    process.kill(parseInt(pid), signal);
    return {
      success: true,
      pid,
      signal,
    };
  },

  // Download file from URL
  async download(args) {
    const { url, destination } = args;
    if (!url) throw new Error('No URL specified');
    if (!destination) throw new Error('No destination specified');

    console.log(`[Agent] Downloading: ${url} -> ${destination}`);

    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const buffer = await response.arrayBuffer();
    await fs.writeFile(destination, Buffer.from(buffer));

    const stats = await fs.stat(destination);
    return {
      success: true,
      url,
      destination,
      size: stats.size,
    };
  },

  // Get environment variables
  async env_get(args) {
    const { name } = args;

    if (name) {
      return {
        success: true,
        name,
        value: process.env[name] || null,
      };
    }

    // Return all (limited for security)
    const safeEnvKeys = ['PATH', 'HOME', 'USER', 'SHELL', 'LANG', 'TERM', 'PWD'];
    const env = {};
    for (const key of safeEnvKeys) {
      if (process.env[key]) {
        env[key] = process.env[key];
      }
    }

    return {
      success: true,
      env,
    };
  },

  // Get current status (heartbeat response)
  async status() {
    return {
      success: true,
      clientId: config.clientId,
      hostname: os.hostname(),
      platform: os.platform(),
      uptime: os.uptime(),
      loadavg: os.loadavg(),
      freemem: os.freemem(),
      totalmem: os.totalmem(),
      timestamp: new Date().toISOString(),
    };
  },
};

// =============================================
// WebSocket Client
// =============================================
class AgentClient {
  constructor() {
    this.ws = null;
    this.heartbeatTimer = null;
    this.reconnecting = false;
  }

  connect() {
    console.log(`[Agent] Connecting to ${config.serverUrl}...`);

    this.ws = new WebSocket(config.serverUrl);

    this.ws.on('open', () => {
      console.log('[Agent] Connected to server');
      this.register();
      this.startHeartbeat();
    });

    this.ws.on('message', async (data) => {
      try {
        const message = JSON.parse(data.toString());
        await this.handleMessage(message);
      } catch (error) {
        console.error('[Agent] Error handling message:', error);
      }
    });

    this.ws.on('close', () => {
      console.log('[Agent] Disconnected from server');
      this.stopHeartbeat();
      this.scheduleReconnect();
    });

    this.ws.on('error', (error) => {
      console.error('[Agent] WebSocket error:', error.message);
    });
  }

  register() {
    this.send({
      type: 'register',
      clientId: config.clientId,
      authSecret: config.clientSecret,
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      username: os.userInfo().username,
    });
  }

  async handleMessage(message) {
    switch (message.type) {
      case 'registered':
        console.log(`[Agent] Registered as: ${message.clientId}`);
        break;

      case 'command': {
        const { commandId, command, args = {} } = message;
        console.log(`[Agent] Received command: ${command} (${commandId})`);

        const handler = commandHandlers[command];
        if (!handler) {
          this.send({
            type: 'command_error',
            commandId,
            error: `Unknown command: ${command}`,
          });
          return;
        }

        try {
          const result = await handler(args);
          this.send({
            type: 'command_response',
            commandId,
            result,
          });
        } catch (error) {
          this.send({
            type: 'command_error',
            commandId,
            error: error.message,
          });
        }
        break;
      }

      case 'heartbeat_ack':
        // Heartbeat acknowledged
        break;

      case 'error':
        console.error(`[Agent] Server error: ${message.message}`);
        break;

      default:
        console.log(`[Agent] Unknown message type: ${message.type}`);
    }
  }

  send(data) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }

  startHeartbeat() {
    this.heartbeatTimer = setInterval(() => {
      this.send({ type: 'heartbeat' });
    }, config.heartbeatInterval);
  }

  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  scheduleReconnect() {
    if (this.reconnecting) return;
    this.reconnecting = true;

    console.log(`[Agent] Reconnecting in ${config.reconnectInterval / 1000}s...`);
    setTimeout(() => {
      this.reconnecting = false;
      this.connect();
    }, config.reconnectInterval);
  }
}

// =============================================
// Main
// =============================================
console.log(`
╔══════════════════════════════════════════════════╗
║         MCP Remote Agent Client v1.0.0           ║
╠══════════════════════════════════════════════════╣
║  Server:    ${config.serverUrl.padEnd(36)}║
║  Client ID: ${config.clientId.padEnd(36).slice(0, 36)}║
║  Hostname:  ${os.hostname().padEnd(36).slice(0, 36)}║
╚══════════════════════════════════════════════════╝
`);

const agent = new AgentClient();
agent.connect();

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('[Agent] Shutting down...');
  agent.ws?.close();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('[Agent] Shutting down...');
  agent.ws?.close();
  process.exit(0);
});
