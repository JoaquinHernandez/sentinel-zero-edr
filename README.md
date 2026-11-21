# sentinel-zero-edr
# SentinelZero — Open-Source EDR, XDR & Zero Trust Prototype

A lightweight, cross-platform Endpoint Detection & Response (EDR), Firewall Manager, and Zero Trust orchestration platform built with **Node.js, React, SQLite (WAL mode), and Tailwind CSS**.

## Architecture

```text
[ Windows / Linux / macOS Agents ]  <--- WebSocket (Telemetry + Commands) --->  [ Node.js Control Plane ]
         |                                                                             |          |
  (OS Native Wrappers)                                                           (SQLite WAL)  (REST API)
  - Ports: netstat / ss / lsof                                                                    |
  - Logs:  WinEvent / journalctl / log stream                                          [ React + Tailwind UI ]
  - FW:    netsh / iptables / pfctl
