# PortIO — Enhanced Port & Connection Management Toolkit (CLI + GUI)

⚠️ **LICENSE & USAGE NOTICE — READ FIRST**

This repository is **source-available for private technical evaluation and testing only**.

- ❌ No commercial use  
- ❌ No production use  
- ❌ No academic, institutional, or government use  
- ❌ No research, benchmarking, or publication  
- ❌ No redistribution, sublicensing, or derivative works  
- ❌ No independent development based on this code  

All rights remain exclusively with the author.  
Use of this software constitutes acceptance of the terms defined in **LICENSE.txt**.

---

**PortIO** is a Python-based network port and connection management tool that combines:

- a scriptable **CLI**,
- a feature-rich **GUI**, and
- a thoroughly tested **core engine**

for inspecting active connections, managing ports, reserving sockets, and interacting with Windows Firewall rules in a controlled, explicit manner.

It is designed primarily for **local development**, **debugging**, and **system administration** workflows.

---

## Features

### Connection inspection
- Enumerate active TCP and UDP connections using `psutil`
- Display local / remote addresses, protocol, state, PID, and process name
- Export netstat-style snapshots to disk

### Port management
- Check whether a port is currently in use
- Start and stop temporary TCP or UDP servers
- Explicitly terminate a process by PID (with confirmation)
- Block or unblock ports via Windows Firewall rules (`netsh advfirewall`)

### Port reservation system
- Reserve a port by binding a persistent socket
- Optionally associate a reservation with a specific executable
- Persist reservations in `port_reservations.json`
- Automatically reload and rebind reservations on startup
- Cleanly release reservations and firewall rules

### Graphical interface
- Tkinter + ttkbootstrap GUI
- Live connection table with refresh and filtering
- Context menu actions (kill, block, reserve, open)
- Netstat-style output viewer
- Port reservation controls with executable browsing

### CLI interface
- Scriptable command-line interface via `argparse`
- Suitable for automation and testing
- Explicit validation of ports and arguments

### Test coverage
- Unit and integration-style tests for:
  - port reservation lifecycle
  - server start/stop behaviour
  - firewall rule handling
  - CLI commands
  - ZeroMQ PUB/SUB port usage scenarios

All tests are designed to fail safely and clean up after themselves. :contentReference[oaicite:0]{index=0}

---

## Project structure
```text
src/
├── core.py # PortManager core logic
├── cli.py # CLI entry point
├── gui.py # Main GUI application
├── portviewer.py # Alternative GUI viewer
├── port_reservations.json
└── port_logs.txt # Generated at runtime
tests/
├── port_reservation_test.py
├── portmaster_test.py
└── server_test.py
```

---

## Requirements

- Python 3.x
- `psutil`
- `ttkbootstrap`
- Windows (for firewall features)

Optional (tests only):
- `pytest`
- `pyzmq` (ZeroMQ test scenarios)

Install dependencies:
```bash
pip install psutil ttkbootstrap pyzmq pytest
```
---

## Usage

### CLI

Run:
```bash
python cli.py --help
```
### Available commands include:

- list
- check-port <port>
- kill <pid>
- block <port> <TCP|UDP>
- unblock <port> <TCP|UDP>
- start-server <port> <TCP|UDP>
- stop-server
- reserve <port> <TCP|UDP> [--exe-path <path>]
- release <port>
- save <filename>

### Examples:

#### List active connections
```bash
python cli.py list
```
#### Check if port 8080 is in use
```bash
python cli.py check-port 8080
```
#### Reserve a port for a specific executable
```bash
python cli.py reserve 8083 TCP --exe-path "C:\Windows\System32\notepad.exe"
```
#### Start a temporary TCP server
```bash
python cli.py start-server 9000 TCP
```
---

### GUI

Run:
```bash
python gui.py
```
The GUI provides:

- live connection scanning
- right-click context actions
- server controls
- reservation management
- netstat-style output viewing

### Platform notes
- Firewall features rely on Windows netsh advfirewall
- Administrative privileges are required for:
  - ports below 1024
  - firewall rule creation/removal
  - process termination
- Non-Windows platforms will still support connection inspection, but firewall features will not apply.

### Safety & intent

⚠️ This tool can terminate processes and modify local firewall rules.

It is intended only for systems you own or administer, and all potentially destructive actions require explicit user confirmation.

---

### Why this exists

PortIO was built to solve recurring developer and admin problems:

- “What is actually holding this port?”
- “Why won’t my service bind?”
- “Can I temporarily reserve a port across restarts?”
- “Which process opened this socket?”
- “How do I cleanly unblock everything after a test run?”

Rather than relying on scattered tools (netstat, Task Manager, PowerShell, ad-hoc scripts), PortIO centralises these workflows into a single, auditable utility.

## Contribution Policy

Feedback, bug reports, and suggestions are welcome.

You may submit:

- Issues
- Design feedback
- Pull requests for review

However:

- Contributions do not grant any license or ownership rights
- The author retains full discretion over acceptance and future use
- Contributors receive no rights to reuse, redistribute, or derive from this code

---

### License
This project is not open-source.

It is licensed under a private evaluation-only license.
See LICENSE.txt for full terms.#
