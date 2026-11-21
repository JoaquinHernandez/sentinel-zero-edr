import express from 'express';
import cors from 'cors';
import http from 'node:http';
import net from 'node:net';
import { WebSocketServer } from 'ws';
import db from './db.js';

const PORT = process.env.PORT || 4000;
const API_SECRET = process.env.AGENT_SECRET || 'change-me-in-prod';

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Map of agentId -> active WebSocket connection
const connectedAgents = new Map();

// Simple detection rules for EDR/XDR alerting
const SUSPICIOUS_PORTS = new Set(['4444', '1337', '31337', '5555', '6667']);
const SUSPICIOUS_LOG_PATTERNS = [
  { regex: /failed password|authentication failure/i, title: 'Brute-Force / Auth Failure', severity: 'MEDIUM' },
  { regex: /powershell.*-enc|nc\s+-e|\/bin\/sh\s+-i/i, title: 'Potential Reverse Shell / Encoded Payload', severity: 'CRITICAL' },
  { regex: /sudo:.*incorrect password/i, title: 'Failed Privilege Escalation Attempt', severity: 'HIGH' }
];

const insertAlert = db.prepare(
  'INSERT INTO alerts (agent_id, severity, title, details, timestamp) VALUES (?, ?, ?, ?, ?)'
);
const insertLog = db.prepare(
  'INSERT INTO logs (agent_id, source, level, message, timestamp) VALUES (?, ?, ?, ?, ?)'
);

function evaluateTelemetry(agentId, ports = [], logs = []) {
  const now = new Date().toISOString();

  for (const p of ports) {
    const portNum = String(p.localAddress || '').split(':').pop();
    if (SUSPICIOUS_PORTS.has(portNum)) {
      insertAlert.run(
        agentId,
        'HIGH',
        `Suspicious Listening Port (${portNum})`,
        `Process ${p.processName || 'unknown'} (PID ${p.pid}) is bound to ${p.localAddress}`,
        now
      );
    }
  }

  for (const entry of logs) {
    for (const rule of SUSPICIOUS_LOG_PATTERNS) {
      if (rule.regex.test(entry.message)) {
        insertAlert.run(agentId, rule.severity, rule.title, entry.message.slice(0, 300), now);
      }
    }
  }
}

// WebSocket handler for Endpoint Agents
wss.on('connection', (ws, req) => {
  const token = req.headers['x-agent-secret'];
  if (token !== API_SECRET) {
    ws.close(1008, 'Unauthorized');
    return;
  }

  let currentAgentId = null;

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      const now = new Date().toISOString();

      if (msg.type === 'register') {
        currentAgentId = msg.agentId;
        connectedAgents.set(currentAgentId, ws);

        db.prepare(`
          INSERT INTO agents (id, hostname, platform, arch, ip, status, last_seen)
          VALUES (?, ?, ?, ?, ?, 'online', ?)
          ON CONFLICT(id) DO UPDATE SET
            hostname = excluded.hostname,
            platform = excluded.platform,
            arch = excluded.arch,
            ip = excluded.ip,
            status = 'online',
            last_seen = excluded.last_seen
        `).run(currentAgentId, msg.hostname, msg.platform, msg.arch, msg.ip || req.socket.remoteAddress, now);
      }

      if (msg.type === 'ports' && currentAgentId) {
        const replacePorts = db.transaction((portsList) => {
          db.prepare('DELETE FROM ports WHERE agent_id = ?').run(currentAgentId);
          const stmt = db.prepare(
            'INSERT INTO ports (agent_id, protocol, local_address, pid, process_name, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
          );
          for (const p of portsList) {
            stmt.run(currentAgentId, p.protocol, p.localAddress, String(p.pid), p.processName, now);
          }
        });
        replacePorts(msg.data || []);
        db.prepare('UPDATE agents SET last_seen = ?, status = ? WHERE id = ?').run(now, 'online', currentAgentId);
        evaluateTelemetry(currentAgentId, msg.data || [], []);
      }

      if (msg.type === 'log' && currentAgentId) {
        const entry = msg.data;
        insertLog.run(currentAgentId, entry.source || 'endpoint', entry.level || 'INFO', entry.message, now);
        evaluateTelemetry(currentAgentId, [], [entry]);
      }

      if (msg.type === 'command_result' && currentAgentId) {
        insertLog.run(
          currentAgentId,
          'response-engine',
          msg.success ? 'INFO' : 'ERROR',
          `Action [${msg.action}]: ${msg.details}`,
          now
        );
      }
    } catch (err) {
      console.error('WS message parse error:', err.message);
    }
  });

  ws.on('close', () => {
    if (currentAgentId) {
      connectedAgents.delete(currentAgentId);
      db.prepare('UPDATE agents SET status = ? WHERE id = ?').run('offline', currentAgentId);
    }
  });
});

function sendAgentCommand(agentId, payload) {
  const ws = connectedAgents.get(agentId);
  if (!ws || ws.readyState !== 1) {
    return false;
  }
  ws.send(JSON.stringify(payload));
  return true;
}

// --- REST API for Dashboard ---

app.get('/api/overview', (req, res) => {
  const agents = db.prepare('SELECT * FROM agents ORDER BY last_seen DESC').all();
  const alerts = db.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT 50').all();
  const logs = db.prepare('SELECT * FROM logs ORDER BY id DESC LIMIT 100').all();
  const blockedIps = db.prepare('SELECT * FROM blocked_ips ORDER BY id DESC').all();
  res.json({ agents, alerts, logs, blockedIps });
});

app.get('/api/agents/:id/ports', (req, res) => {
  const ports = db.prepare('SELECT * FROM ports WHERE agent_id = ? ORDER BY local_address ASC').all(req.params.id);
  res.json(ports);
});

app.post('/api/agents/:id/block-ip', (req, res) => {
  const { ip } = req.body;
  if (!ip || !net.isIP(ip)) {
    return res.status(400).json({ error: 'Valid IPv4 or IPv6 address required' });
  }

  const sent = sendAgentCommand(req.params.id, { type: 'command', action: 'block_ip', ip });
  if (!sent) return res.status(404).json({ error: 'Agent offline' });

  db.prepare('INSERT INTO blocked_ips (agent_id, ip, created_at) VALUES (?, ?, ?)').run(
    req.params.id,
    ip,
    new Date().toISOString()
  );
  res.json({ status: 'command_sent', ip });
});

app.post('/api/agents/:id/kill-pid', (req, res) => {
  const pid = Number(req.body.pid);
  if (!Number.isInteger(pid) || pid <= 1) {
    return res.status(400).json({ error: 'Valid PID (> 1) required' });
  }

  const sent = sendAgentCommand(req.params.id, { type: 'command', action: 'kill_pid', pid });
  if (!sent) return res.status(404).json({ error: 'Agent offline' });

  res.json({ status: 'command_sent', pid });
});

app.post('/api/agents/:id/isolate', (req, res) => {
  const enable = Boolean(req.body.enable);
  const sent = sendAgentCommand(req.params.id, { type: 'command', action: 'isolate', enable });
  if (!sent) return res.status(404).json({ error: 'Agent offline' });

  db.prepare('UPDATE agents SET isolated = ? WHERE id = ?').run(enable ? 1 : 0, req.params.id);
  res.json({ status: 'command_sent', isolated: enable });
});

// --- XDR External Log Ingestion Webhook ---
app.post('/api/xdr/ingest', (req, res) => {
  if (req.headers['x-api-token'] !== API_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const { source = 'external-xdr', level = 'INFO', message } = req.body;
  if (!message) return res.status(400).json({ error: 'message is required' });

  const now = new Date().toISOString();
  insertLog.run('XDR-CLOUD', source, level, message, now);
  if (['HIGH', 'CRITICAL'].includes(String(level).toUpperCase())) {
    insertAlert.run('XDR-CLOUD', level.toUpperCase(), `XDR Alert from ${source}`, message, now);
  }
  res.json({ status: 'ingested' });
});

server.listen(PORT, () => {
  console.log(`SentinelZero Control Plane running on http://localhost:${PORT}`);
});
