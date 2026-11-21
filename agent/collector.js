import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';

const execFileAsync = promisify(execFile);
const platform = os.platform();

/**
 * Collects open network ports and owning processes on Windows, Linux, and macOS.
 */
export async function getOpenPorts() {
  try {
    if (platform === 'linux') {
      const { stdout } = await execFileAsync('ss', ['-tulpn']);
      return parseLinuxSS(stdout);
    }
    if (platform === 'darwin') {
      const { stdout } = await execFileAsync('lsof', ['-i', '-P', '-n']);
      return parseMacLsof(stdout);
    }
    if (platform === 'win32') {
      const [netstatRes, tasklistRes] = await Promise.all([
        execFileAsync('netstat', ['-ano']),
        execFileAsync('tasklist', ['/FO', 'CSV', '/NH'])
      ]);
      return parseWindowsNetstat(netstatRes.stdout, tasklistRes.stdout);
    }
  } catch (err) {
    console.error('Port collection error:', err.message);
  }
  return [];
}

function parseLinuxSS(output) {
  const lines = output.split('\n').slice(1);
  const results = [];
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;
    const protocol = parts[0];
    const localAddress = parts[4];
    const procCol = parts.slice(6).join(' ');
    const pidMatch = procCol.match(/pid=(\d+)/);
    const nameMatch = procCol.match(/"([^"]+)"/);
    results.push({
      protocol,
      localAddress,
      pid: pidMatch ? pidMatch[1] : 'N/A',
      processName: nameMatch ? nameMatch[1] : 'unknown'
    });
  }
  return results;
}

function parseMacLsof(output) {
  const lines = output.split('\n').slice(1);
  const results = [];
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 9) continue;
    results.push({
      processName: parts[0],
      pid: parts[1],
      protocol: parts[7],
      localAddress: parts[8]
    });
  }
  return results;
}

function parseWindowsNetstat(netstatOut, tasklistOut) {
  const pidMap = new Map();
  for (const line of tasklistOut.split('\n')) {
    const cols = line.trim().replace(/^"|"$/g, '').split('","');
    if (cols.length >= 2) pidMap.set(cols[1], cols[0]);
  }

  const results = [];
  for (const line of netstatOut.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts[0] !== 'TCP' && parts[0] !== 'UDP') continue;
    const pid = parts[parts.length - 1];
    results.push({
      protocol: parts[0],
      localAddress: parts[1],
      pid,
      processName: pidMap.get(pid) || 'System'
    });
  }
  return results;
}

/**
 * Streams real-time OS logs safely using native system tools.
 */
export function startLogStream(onLog) {
  if (platform === 'linux') {
    const child = spawn('journalctl', ['-f', '-n', '5', '--no-pager']);
    child.stdout.on('data', (chunk) => {
      for (const line of chunk.toString().split('\n').filter(Boolean)) {
        onLog({ source: 'journald', level: 'INFO', message: line });
      }
    });
    child.on('error', (err) => console.error('journalctl error:', err.message));
    return child;
  }

  if (platform === 'darwin') {
    const child = spawn('log', [
      'stream',
      '--style', 'compact',
      '--predicate', 'eventMessage contains "auth" OR eventMessage contains "sudo" OR eventMessage contains "denied"'
    ]);
    child.stdout.on('data', (chunk) => {
      for (const line of chunk.toString().split('\n').filter(Boolean)) {
        onLog({ source: 'macos-unified-log', level: 'INFO', message: line });
      }
    });
    child.on('error', (err) => console.error('log stream error:', err.message));
    return child;
  }

  if (platform === 'win32') {
    // Poll recent Windows System/Security events every 10s
    const timer = setInterval(async () => {
      try {
        const { stdout } = await execFileAsync('powershell.exe', [
          '-NoProfile',
          '-Command',
          'Get-WinEvent -LogName System -MaxEvents 3 | Select-Object TimeCreated,LevelDisplayName,Message | ConvertTo-Json'
        ]);
        const events = JSON.parse(stdout || '[]');
        const list = Array.isArray(events) ? events : [events];
        for (const ev of list) {
          if (ev?.Message) {
            onLog({
              source: 'win-eventlog',
              level: ev.LevelDisplayName || 'INFO',
              message: ev.Message.replace(/\s+/g, ' ').slice(0, 250)
            });
          }
        }
      } catch {
        // Ignore transient PowerShell polling errors
      }
    }, 10000);
    return { kill: () => clearInterval(timer) };
  }
}
