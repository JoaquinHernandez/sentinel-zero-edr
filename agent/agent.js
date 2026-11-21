import WebSocket from 'ws';
import os from 'node:os';
import { getOpenPorts, startLogStream } from './collector.js';
import { blockIP, killProcess, setZeroTrustIsolation } from './firewall.js';

const SERVER_URL = process.env.SERVER_URL || 'ws://localhost:4000';
const AGENT_SECRET = process.env.AGENT_SECRET || 'change-me-in-prod';
const AGENT_ID = `${os.hostname()}-${os.platform()}`;

const serverHost = new URL(SERVER_URL).hostname;
let ws;
let portTimer;
let logProcess;

function connect() {
  ws = new WebSocket(SERVER_URL, {
    headers: { 'x-agent-secret': AGENT_SECRET }
  });

  ws.on('open', () => {
    console.log(`[SentinelZero Agent] Connected to ${SERVER_URL} as ${AGENT_ID}`);
    ws.send(JSON.stringify({
      type: 'register',
      agentId: AGENT_ID,
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch()
    }));

    // Poll open ports every 5 seconds
    const pushPorts = async () => {
      if (ws.readyState !== 1) return;
      const ports = await getOpenPorts();
      ws.send(JSON.stringify({ type: 'ports', data: ports }));
    };
    pushPorts();
    portTimer = setInterval(pushPorts, 5000);

    // Stream system logs
    logProcess = startLogStream((entry) => {
      if (ws.readyState === 1) {
        ws.send(JSON.stringify({ type: 'log', data: entry }));
      }
    });
  });

  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type !== 'command') return;

      let details = '';
      if (msg.action === 'block_ip') {
        details = await blockIP(msg.ip);
      } else if (msg.action === 'kill_pid') {
        details = await killProcess(msg.pid);
      } else if (msg.action === 'isolate') {
        details = await setZeroTrustIsolation(msg.enable, serverHost);
      }

      ws.send(JSON.stringify({
        type: 'command_result',
        action: msg.action,
        success: true,
        details
      }));
    } catch (err) {
      ws.send(JSON.stringify({
        type: 'command_result',
        action: 'error',
        success: false,
        details: err.message
      }));
    }
  });

  ws.on('close', () => {
    console.log('[SentinelZero Agent] Disconnected. Reconnecting in 5s...');
    clearInterval(portTimer);
    if (logProcess?.kill) logProcess.kill();
    setTimeout(connect, 5000);
  });

  ws.on('error', (err) => {
    console.error('[SentinelZero Agent] WS Error:', err.message);
  });
}

connect();
