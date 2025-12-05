#!/usr/bin/env node
/**
 * Test script for Havoc MCP Bridge
 */

import WebSocket from 'ws';
import crypto from 'crypto';

// Use wss:// and reject unauthorized false for self-signed certs
const TEAMSERVER = 'wss://127.0.0.1:40056/service';
const PASSWORD = 'mcp-service-test';

console.log('=== Havoc MCP Bridge Test ===\n');
console.log(`Connecting to: ${TEAMSERVER}`);

const ws = new WebSocket(TEAMSERVER, {
  rejectUnauthorized: false  // Accept self-signed certs
});

ws.on('open', () => {
  console.log('[+] WebSocket connected (TLS)');

  // Authenticate
  const authMsg = {
    Head: { Type: 'Register' },
    Body: { Password: PASSWORD }
  };

  console.log('[*] Sending authentication...');
  ws.send(JSON.stringify(authMsg));
});

ws.on('message', (data) => {
  const msg = JSON.parse(data.toString());
  console.log('[<] Received:', JSON.stringify(msg, null, 2));

  if (msg.Head?.Type === 'Register') {
    if (msg.Body?.Success) {
      console.log('\n[+] Authentication successful!');
      console.log('[+] MCP-Havoc bridge is working!\n');

      // Register our MCP agent type
      const agentReg = {
        Head: { Type: 'RegisterAgent' },
        Body: {
          Agent: {
            Name: 'MCP-Test-Agent',
            Description: 'Claude MCP Test Agent',
            Version: '1.0.0',
            Author: 'Claude C2',
            MagicValue: '0x4D435054',
            Arch: ['x64'],
            Formats: [{ Name: 'Test', Extension: 'txt' }],
            Commands: [
              { Name: 'test', Description: 'Test command' }
            ]
          }
        }
      };

      console.log('[*] Registering MCP agent type...');
      ws.send(JSON.stringify(agentReg));

      // Wait a bit then close
      setTimeout(() => {
        console.log('\n[+] Test complete - bridge is functional');
        ws.close();
        process.exit(0);
      }, 2000);

    } else {
      console.log('[-] Authentication failed');
      ws.close();
      process.exit(1);
    }
  }
});

ws.on('error', (err) => {
  console.error('[-] WebSocket error:', err.message);
  process.exit(1);
});

ws.on('close', () => {
  console.log('[*] Connection closed');
});
