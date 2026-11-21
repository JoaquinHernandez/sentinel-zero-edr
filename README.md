# sentinel-zero-edr
# SentinelZero — Open-Source EDR, XDR & Zero Trust Prototype
<img width="1024" height="572" alt="image" src="https://github.com/user-attachments/assets/f8517318-9940-42ad-a81d-f8d807c20d0c" />

<p align="center">
  <img src="banner.png" alt="SentinelZero Banner" width="100%" />
</p>

<p align="center">
  <a href="#about"><img src="https://img.shields.io/badge/Security-BlueTeam-emerald?style=for-the-badge&logo=shield" alt="Security BlueTeam" /></a>
  <a href="#frameworks"><img src="https://img.shields.io/badge/Stack-Node%20%7C%20React%20%7C%20SQLite%20%7C%20Tailwind-blue?style=for-the-badge" alt="Stack" /></a>
  <a href="#license"><img src="https://img.shields.io/github/license/username/sentinel-zero-edr?style=for-the-badge&color=gray" alt="License" /></a>
  <img src="https://img.shields.io/badge/Status-Prototype-orange?style=for-the-badge" alt="Status" />
</p>

---

## ⚡ SentinelZero: Open-Source EDR, XDR & Zero Trust Prototype

`SentinelZero` is a lightweight, cross-platform Endpoint Detection & Response (EDR), Firewall Manager, and Zero Trust orchestration prototype. Built entirely with **Node.js (v20+), React, SQLite (WAL mode), and Tailwind CSS**, it provides security operators with real-time process monitoring, live host isolation, network socket visibility, and immediate defense-in-depth enforcement from a single web-based SOC dashboard.

⚠️ **Disclaimer:** *This is a user-space proof of concept (PoC) for education, red/blue-team simulation, and showcase purposes. Review [Security & Tamper Notes](#-security--tamper-resistance-caveats) before deploying on critical assets.*

---

## 🏗️ Architecture

```text
[ Windows / Linux / macOS Agents ]  <--- WebSocket (Telemetry + Commands) --->  [ Node.js Control Plane ]
         |                                                                             |          |
  (OS Native Wrappers)                                                           (SQLite WAL)  (REST API)
  ├── Ports: netstat / ss / lsof                                                                │
  ├── Logs:  WinEvent / journalctl / log stream                                                 ▼
  └── FW:    netsh / iptables / pfctl                                               [ React + Tailwind UI ]

Key ComponentsThe Control Plane (Server): Written in Node.js, this central hub ingests stream telemetry, executes rule engines, processes threat detection alerts, and routes socket command requests. It exposes WebSocket connections for fast response and REST APIs for control.The Endpoint Agent (Node client): Packed down for any platform. Subscribes to endpoint OS utility calls and commands back natively. Runs as a daemon (root/SYSTEM).The Web Dashboard (Frontend): Responsive React, Vite, and Tailwind UI, with multi-view tracking (Devices, Ports, Firewall, Live Logs, Alerts).🛡️ Feature Matrix🔍 Real-Time Port & App Mapping: Tracks listening IP/Ports alongside PIDs and owning executable names across Windows, Linux, and macOS.📜 Live Log Telemetry: Stream process logs, auth failures, OS notifications (journald, MacOS Unified Log, Win Events) via secure protocols.🔒 Zero Trust Isolation (Default-Deny): Immediatly drops inbound & outbound traffic on an endpoint via iptables/netsh while keeping the Control Plane IP whitelisted.🛑 Active Response: Remotely terminate rogue PIDs, isolate compromised hosts, or block suspicious IPs.🔬 Detection Engine: Pre-built alerting logic checking log streams and suspicious ports (4444, 31337, etc) using Sigma-style criteria.🌐 XDR Integration Webhook: Inject outside firewall or cloud events through POST (/api/xdr/ingest).🚀 Quick StartPrerequisitesNode.js (v18.x or above)Administrator/Root access on target endpoint machines.1. Control Plane Setup (Server)Bashcd server
npm install
npm start
Port: http://localhost:40002. SOC Dashboard Setup (Client)Bashcd client
npm install
npm run dev
Access dashboard: http://localhost:51733. Run Agent (Administrative Access)Linux / macOS:Bashcd agent
npm install
sudo SERVER_URL=ws://localhost:4000 AGENT_SECRET=change-me-in-prod node agent.js
Windows (PowerShell as Administrator):PowerShellcd agent
npm install
$env:SERVER_URL="ws://localhost:4000"
$env:AGENT_SECRET="change-me-in-prod"
node agent.js
📡 XDR Webhook Ingestion ExampleIntegrate firewalls, IAM, or cloud logs to correlate with endpoint events:Bashcurl -X POST http://localhost:4000/api/xdr/ingest \
  -H "Content-Type: application/json" \
  -H "x-api-token: change-me-in-prod" \
  -d '{
    "source": "aws-cloudtrail",
    "level": "HIGH",
    "message": "Unauthorized IAM policy attachment by unknown user"
  }'
🔥 Defensive vs Offensive Trade-OffsDefensive Strengths (EDR/XDR)Offensive Evasion / Weaknesses (Security SME Perspective)Active Blocking: Quick OS isolation for compromised hosts.Subversion: Runs in user-space. Privilege escalation allows attackers to kill node or clear firewall tables.Consolidated Logs: Pulls OS and application events together.Poll Frequency: Interval check loop allows micro-connections to execute and die before a poll.Command Execution: Avoids execution strings using strict parameterized binaries.SOC Takeover: If Server API is broken, attackers gain network-wide Command RCE. Secure APIs strictly.🛣️ Roadmap[ ] Integrate SQLite schema and Agent payloads over HTTPS and TLS/mTLS.[ ] Support custom YAML rule sets matching Sigma structures.[ ] Migrate Agent from user-space scripts to Rust/Go for ETW (Windows), eBPF (Linux), and ESF (macOS).[ ] Introduce process authentication (signing certificate validating).📄 LicenseThis project is licensed under the MIT License - see LICENSE for details.
***

### Showcase Your Work
Upload this `README.md` and use the high-fidelity banner image below to get a head-turning presentation on your GitHub repository:

### Generated Repository Image
Use this image as `banner.png` in the root of your project:

http://googleusercontent.com/image_generation_content/2_1040

