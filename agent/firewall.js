import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import net from 'node:net';

const execFileAsync = promisify(execFile);
const platform = os.platform();

/**
 * Blocks an IP address using the native OS firewall.
 * Strictly validates IP format to prevent command injection.
 */
export async function blockIP(ip) {
  if (!net.isIP(ip)) {
    throw new Error('Invalid IP address format');
  }

  if (platform === 'linux') {
    await execFileAsync('iptables', ['-A', 'INPUT', '-s', ip, '-j', 'DROP']);
    await execFileAsync('iptables', ['-A', 'OUTPUT', '-d', ip, '-j', 'DROP']);
  } else if (platform === 'win32') {
    const ruleName = `SentinelZero_Block_${ip}`;
    await execFileAsync('netsh', [
      'advfirewall', 'firewall', 'add', 'rule',
      `name=${ruleName}`, 'dir=in', 'action=block', `remoteip=${ip}`
    ]);
    await execFileAsync('netsh', [
      'advfirewall', 'firewall', 'add', 'rule',
      `name=${ruleName}_OUT`, 'dir=out', 'action=block', `remoteip=${ip}`
    ]);
  } else if (platform === 'darwin') {
    await execFileAsync('pfctl', ['-t', 'zt_blocked', '-T', 'add', ip]);
  } else {
    throw new Error(`Unsupported OS: ${platform}`);
  }

  return `Blocked IP ${ip} via native ${platform} firewall`;
}

/**
 * Terminates a running process by PID.
 */
export async function killProcess(pid) {
  const numPid = Number(pid);
  if (!Number.isInteger(numPid) || numPid <= 1) {
    throw new Error('Invalid PID');
  }

  if (platform === 'win32') {
    await execFileAsync('taskkill', ['/F', '/PID', String(numPid)]);
  } else {
    await execFileAsync('kill', ['-9', String(numPid)]);
  }
  return `Terminated PID ${numPid}`;
}

/**
 * Zero Trust Host Isolation (Default-Deny while allowing Control Plane IP).
 */
export async function setZeroTrustIsolation(enable, controlPlaneHost) {
  if (platform === 'linux') {
    if (enable) {
      await execFileAsync('iptables', ['-P', 'INPUT', 'DROP']);
      await execFileAsync('iptables', ['-P', 'OUTPUT', 'DROP']);
      await execFileAsync('iptables', ['-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT']);
      await execFileAsync('iptables', ['-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT']);
      if (net.isIP(controlPlaneHost)) {
        await execFileAsync('iptables', ['-A', 'OUTPUT', '-d', controlPlaneHost, '-j', 'ACCEPT']);
        await execFileAsync('iptables', ['-A', 'INPUT', '-s', controlPlaneHost, '-j', 'ACCEPT']);
      }
      return 'Zero Trust isolation ENABLED (Linux iptables default-deny)';
    } else {
      await execFileAsync('iptables', ['-P', 'INPUT', 'ACCEPT']);
      await execFileAsync('iptables', ['-P', 'OUTPUT', 'ACCEPT']);
      await execFileAsync('iptables', ['-F']);
      return 'Zero Trust isolation DISABLED (Linux iptables reset)';
    }
  }

  if (platform === 'win32') {
    const policy = enable ? 'blockinbound,blockoutbound' : 'blockinbound,allowoutbound';
    await execFileAsync('netsh', ['advfirewall', 'set', 'allprofiles', 'firewallpolicy', policy]);
    return `Zero Trust isolation ${enable ? 'ENABLED' : 'DISABLED'} (Windows Firewall)`;
  }

  return `Zero Trust isolation toggle logged for ${platform} (configure pf.conf for macOS full isolation)`;
}
