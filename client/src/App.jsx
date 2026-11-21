import React, { useEffect, useState } from 'react';
import { ShieldAlert, Terminal, Network, Lock, Skull, Ban, Activity } from 'lucide-react';

const API = 'http://localhost:4000/api';

export default function App() {
  const [data, setData] = useState({ agents: [], alerts: [], logs: [], blockedIps: [] });
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [ports, setPorts] = useState([]);
  const [ipInput, setIpInput] = useState('');
  const [activeTab, setActiveTab] = useState('ports');
  const [statusMsg, setStatusMsg] = useState('');

  const fetchOverview = async () => {
    try {
      const res = await fetch(`${API}/overview`);
      const json = await res.json();
      setData(json);
      if (!selectedAgent && json.agents.length > 0) {
        setSelectedAgent(json.agents[0].id);
      }
    } catch {
      // Server offline
    }
  };

  const fetchPorts = async (agentId) => {
    if (!agentId) return;
    try {
      const res = await fetch(`${API}/agents/${encodeURIComponent(agentId)}/ports`);
      setPorts(await res.json());
    } catch {
      setPorts([]);
    }
  };

  useEffect(() => {
    fetchOverview();
    const timer = setInterval(fetchOverview, 3000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!selectedAgent) return;
    fetchPorts(selectedAgent);
    const timer = setInterval(() => fetchPorts(selectedAgent), 3000);
    return () => clearInterval(timer);
  }, [selectedAgent]);

  const sendAction = async (endpoint, body) => {
    if (!selectedAgent) return;
    const res = await fetch(`${API}/agents/${encodeURIComponent(selectedAgent)}/${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const json = await res.json();
    setStatusMsg(json.error ? `Error: ${json.error}` : `Action dispatched: ${endpoint}`);
    fetchOverview();
  };

  const currentAgentObj = data.agents.find((a) => a.id === selectedAgent);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 font-sans">
      <header className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-8 h-8 text-emerald-400" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">SentinelZero EDR / XDR</h1>
            <p className="text-xs text-slate-400">Cross-Platform Zero Trust & Firewall Control Plane</p>
          </div>
        </div>
        {statusMsg && (
          <div className="text-xs bg-slate-900 border border-emerald-500/40 text-emerald-300 px-3 py-1.5 rounded">
            {statusMsg}
          </div>
        )}
      </header>

      {/* Top Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <MetricCard label="Connected Endpoints" value={data.agents.filter((a) => a.status === 'online').length} />
        <MetricCard label="Open Ports (Selected)" value={ports.length} />
        <MetricCard label="Active Alerts" value={data.alerts.length} highlight="text-rose-400" />
        <MetricCard label="Blocked IPs" value={data.blockedIps.length} highlight="text-amber-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Agent Sidebar */}
        <aside className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Endpoints</h2>
          <div className="space-y-2">
            {data.agents.length === 0 && (
              <p className="text-xs text-slate-500">No agents connected. Start the agent with root/admin privileges.</p>
            )}
            {data.agents.map((agent) => (
              <button
                key={agent.id}
                onClick={() => setSelectedAgent(agent.id)}
                className={`w-full text-left p-3 rounded-lg border transition ${
                  selectedAgent === agent.id
                    ? 'bg-slate-800 border-emerald-500/60'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-sm">{agent.hostname}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full ${
                    agent.status === 'online' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-700 text-slate-400'
                  }`}>
                    {agent.status}
                  </span>
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  OS: {agent.platform} ({agent.arch})
                </div>
                {agent.isolated === 1 && (
                  <div className="text-[10px] text-rose-400 font-semibold mt-1">ZERO TRUST ISOLATED</div>
                )}
              </button>
            ))}
          </div>

          {currentAgentObj && (
            <div className="mt-6 pt-4 border-t border-slate-800">
              <button
                onClick={() => sendAction('isolate', { enable: !currentAgentObj.isolated })}
                className={`w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-semibold ${
                  currentAgentObj.isolated
                    ? 'bg-emerald-600 hover:bg-emerald-500'
                    : 'bg-rose-600 hover:bg-rose-500'
                }`}
              >
                <Lock className="w-4 h-4" />
                {currentAgentObj.isolated ? 'Lift Zero Trust Isolation' : 'Isolate Host (Zero Trust)'}
              </button>
            </div>
          )}
        </aside>

        {/* Main Workspace */}
        <main className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex gap-2 border-b border-slate-800 pb-3 mb-4">
            <TabButton active={activeTab === 'ports'} onClick={() => setActiveTab('ports')} icon={<Network className="w-4 h-4" />} label="Open Ports & Apps" />
            <TabButton active={activeTab === 'firewall'} onClick={() => setActiveTab('firewall')} icon={<Ban className="w-4 h-4" />} label="Firewall Rules" />
            <TabButton active={activeTab === 'alerts'} onClick={() => setActiveTab('alerts')} icon={<Activity className="w-4 h-4" />} label={`Alerts (${data.alerts.length})`} />
            <TabButton active={activeTab === 'logs'} onClick={() => setActiveTab('logs')} icon={<Terminal className="w-4 h-4" />} label="Live Logs & XDR" />
          </div>

          {activeTab === 'ports' && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="py-2">Protocol</th>
                    <th className="py-2">Local Address / Port</th>
                    <th className="py-2">PID</th>
                    <th className="py-2">Application</th>
                    <th className="py-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {ports.map((p, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/40">
                      <td className="py-2 uppercase font-mono text-emerald-400">{p.protocol}</td>
                      <td className="py-2 font-mono">{p.local_address}</td>
                      <td className="py-2 font-mono text-slate-300">{p.pid}</td>
                      <td className="py-2 font-medium">{p.process_name}</td>
                      <td className="py-2 text-right">
                        {Number(p.pid) > 1 && (
                          <button
                            onClick={() => sendAction('kill-pid', { pid: Number(p.pid) })}
                            className="inline-flex items-center gap-1 bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 px-2 py-1 rounded"
                          >
                            <Skull className="w-3 h-3" /> Kill
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'firewall' && (
            <div>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  sendAction('block-ip', { ip: ipInput.trim() });
                  setIpInput('');
                }}
                className="flex gap-2 mb-5"
              >
                <input
                  type="text"
                  value={ipInput}
                  onChange={(e) => setIpInput(e.target.value)}
                  placeholder="Enter IPv4 or IPv6 to block (e.g. 203.0.113.45)"
                  className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
                />
                <button type="submit" className="bg-rose-600 hover:bg-rose-500 px-4 py-2 rounded-lg text-sm font-semibold">
                  Block IP
                </button>
              </form>
              <div className="space-y-2">
                {data.blockedIps.map((b) => (
                  <div key={b.id} className="flex justify-between bg-slate-950 border border-slate-800 p-3 rounded text-xs font-mono">
                    <span className="text-rose-400">{b.ip}</span>
                    <span className="text-slate-400">Agent: {b.agent_id}</span>
                    <span className="text-slate-500">{new Date(b.created_at).toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {data.alerts.map((a) => (
                <div key={a.id} className="bg-slate-950 border border-rose-500/30 p-3 rounded-lg">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-bold text-rose-400">[{a.severity}] {a.title}</span>
                    <span className="text-slate-500">{new Date(a.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <p className="text-xs text-slate-300 font-mono">{a.details}</p>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 max-h-[500px] overflow-y-auto font-mono text-xs space-y-1.5">
              {data.logs.map((l) => (
                <div key={l.id} className="text-slate-300">
                  <span className="text-slate-500">[{new Date(l.timestamp).toLocaleTimeString()}]</span>{' '}
                  <span className="text-emerald-400">[{l.source}]</span>{' '}
                  <span>{l.message}</span>
                </div>
              ))}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function MetricCard({ label, value, highlight = 'text-slate-100' }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="text-xs text-slate-400">{label}</div>
      <div className={`text-2xl font-bold mt-1 ${highlight}`}>{value}</div>
    </div>
  );
}

function TabButton({ active, onClick, icon, label }) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
        active ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-slate-200'
      }`}
    >
      {icon}
      {label}
    </button>
  );
}
