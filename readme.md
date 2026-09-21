<div align="center">

# 🛡️ PortScan Defender

**Automated Port Scan Detection & Blocking for Linux Servers**

[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-red?style=flat-square&logo=linux)](https://www.debian.org/)
[![Shell](https://img.shields.io/badge/shell-Bash%204.0+-4EAA25?style=flat-square&logo=gnu-bash)](https://www.gnu.org/software/bash/)
[![Firewall](https://img.shields.io/badge/firewall-nftables-orange?style=flat-square)](https://nftables.org/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-success?style=flat-square)]()

*Real-time detection and mitigation of port scanning attacks using kernel-level nftables sets.*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [How It Works](#-how-it-works)
- [Security Model](#-security-model)
- [Logs & Monitoring](#-logs--monitoring)
- [Troubleshooting](#-troubleshooting)
- [Uninstallation](#-uninstallation)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

**PortScan Defender** is a lightweight, production-grade daemon that detects inbound port scanning attempts in real time and blocks the source IP using `nftables` kernel sets.

Unlike traditional fail2ban-style solutions that read log files line by line, this tool leverages:

- **nftables kernel sets** with built-in timeouts → O(1) lookups, automatic expiry, zero CPU overhead for blocked IPs.
- **journalctl streaming** → no log file parsing, no rotation issues.
- **Sliding-window heuristics** → detects both aggressive and stealthy scans.

The tool escalates from **temporary blocks** to **permanent blocks** when the same attacker returns within a configurable window.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🎯 **Multi-Signal Detection** | Port diversity, connection rate, and SYN_RECEIVED analysis |
| ⏱️ **Auto-Expiring Blocks** | Temporary bans are handled entirely in-kernel via nftables `timeout` |
| 🔒 **Permanent Escalation** | Repeat offenders within a configurable window are permanently blocked |
| 🧊 **Whitelist Support** | IP/CIDR and port whitelists that never trigger blocks or logs |
| 🚦 **Rate-Limited Logging** | nftables log rule has a configurable rate limit to prevent log flooding |
| 🛡️ **DoS-Resistant** | Hard cap on total blocked IPs prevents state pollution attacks |
| 🔄 **Persistent State** | Incidents survive service restarts (stored in TSV, atomic writes) |
| ⚙️ **systemd Integrated** | Hardened unit file with sandboxing and resource limits |
| 🔄 **Hot Reload** | Whitelist changes via `SIGHUP` without restarting the service |
| 📊 **CLI Management** | `--status`, `--list`, `--unblock` subcommands |
| 🧹 **Log Rotation** | Automatic rotation at 50 MB |
| 🌐 **Zero Python** | Pure Bash 4.0+ with only `nft`, `jq`, `journalctl`, `ss` as dependencies |

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                        Linux Kernel                            │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │             nftables (table: portscan_defender)          │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐ │  │
│  │  │ whitelist  │  │ temp_block │  │   perm_block       │ │  │
│  │  │   _ips     │  │ (timeout)  │  │   (no timeout)     │ │  │
│  │  └────────────┘  └────────────┘  └────────────────────┘ │  │
│  │                                                          │  │
│  │  input chain (priority -10):                             │  │
│  │    1. accept whitelisted IPs                             │  │
│  │    2. drop permanent blocks                              │  │
│  │    3. drop temporary blocks                              │  │
│  │    4. log new TCP conns on non-whitelisted ports         │  │
│  └─────────────────────────────────────────────────────────┘  │
│                              ▲                                 │
│                              │ log events                      │
└──────────────────────────────┼─────────────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │    journalctl -k    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   portscan-defender │
                    │   (Bash daemon)     │
                    │  ┌───────────────┐  │
                    │  │  Analyzer     │  │
                    │  │  (sliding     │  │
                    │  │   window)     │  │
                    │  └───────┬───────┘  │
                    │          │          │
                    │  ┌───────▼───────┐  │
                    │  │  nft manager  │  │
                    │  │  (add/remove) │  │
                    │  └───────────────┘  │
                    └─────────────────────┘
```

---

## 📦 Requirements

- **OS:** Debian 11+, Ubuntu 20.04 LTS or newer
- **Shell:** Bash 4.0+
- **Tools:** `nftables`, `jq`, `procps`, `iproute2`, `coreutils`, `gawk`
- **Kernel:** nftables enabled (default on all modern distros)
- **Privileges:** root (or systemd capabilities `CAP_NET_ADMIN`, `CAP_NET_RAW`)

Install dependencies:

```bash
sudo apt update
sudo apt install -y nftables jq procps iproute2 coreutils gawk
```

---

## 🚀 Installation

### Quick Install

```bash
# 1) Clone the repository
git clone https://github.com/YOUR_USERNAME/portscan-defender.git
cd portscan-defender

# 2) Run the installer
sudo chmod +x install.sh portscan-defender.sh
sudo ./install.sh
```

### Manual Install

```bash
sudo mkdir -p /opt/portscan-defender /var/lib/portscan-defender /var/log/portscan-defender
sudo install -m 0755 portscan-defender.sh   /opt/portscan-defender/
sudo install -m 0644 portscan-defender.conf /opt/portscan-defender/
sudo install -m 0644 port_whitelist.txt     /opt/portscan-defender/
sudo install -m 0644 portscan-defender.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now portscan-defender
```

### Verify

```bash
sudo systemctl status portscan-defender
sudo /opt/portscan-defender/portscan-defender.sh --status
```

---

## ⚙️ Configuration

Two files control behavior:

### 1. `portscan-defender.conf`

```bash
# Detection thresholds
DETECTION_WINDOW=10              # Seconds to aggregate connection events
PORT_THRESHOLD=15                # Distinct ports from one IP within window
RATE_THRESHOLD=25                # Total new connections from one IP
SYN_THRESHOLD=5                  # Concurrent SYN_RECEIVED connections

# Block policy
TEMP_BLOCK_SECONDS=3600          # Temporary block duration (1h)
REPEAT_WINDOW_SECONDS=86400      # Escalate if seen again within 24h
MAX_BLOCKED_IPS=1000             # Safety cap

# Runtime
POLL_INTERVAL=5                  # Detection loop interval
ENABLE_SYN_DETECTION=1           # 0 to disable SYN-based detection
LOG_RATE_LIMIT=2000              # nftables log rate (packets/sec)

# IP whitelist (never blocked, never logged)
IP_WHITELIST=(
    "127.0.0.0/8"
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "169.254.0.0/16"
    "224.0.0.0/4"
    "240.0.0.0/4"
)
```

### 2. `port_whitelist.txt`

Ports listed here are excluded from detection (no log, no block):

```text
# Public web services
80
443

# DNS / NTP
53
123

# Monitoring stack
9100
9115
9090
3000

# Ranges supported
8000-8100
```

### Applying Changes

```bash
# Whitelist changes only (fast, no interruption)
sudo systemctl reload portscan-defender

# Threshold or policy changes (full restart)
sudo systemctl restart portscan-defender
```

---

## 🎮 Usage

### Service Management

```bash
sudo systemctl start portscan-defender     # Start
sudo systemctl stop portscan-defender      # Stop
sudo systemctl restart portscan-defender   # Restart
sudo systemctl reload portscan-defender    # Reload whitelist (SIGHUP)
sudo systemctl status portscan-defender    # Status
```

### CLI Subcommands

```bash
# Show current status and statistics
/opt/portscan-defender/portscan-defender.sh --status

# List all blocked IPs (temporary + permanent)
/opt/portscan-defender/portscan-defender.sh --list

# List temporary blocks only
/opt/portscan-defender/portscan-defender.sh --list-temp

# List permanent blocks only
/opt/portscan-defender/portscan-defender.sh --list-perm

# Unblock a specific IP
/opt/portscan-defender/portscan-defender.sh --unblock 203.0.113.45

# Help
/opt/portscan-defender/portscan-defender.sh --help
```

### Direct nftables Inspection

```bash
# Full table view
sudo nft list table inet portscan_defender

# Temporary block set (with remaining time)
sudo nft list set inet portscan_defender temp_block

# Permanent block set
sudo nft list set inet portscan_defender perm_block

# Whitelist IPs
sudo nft list set inet portscan_defender whitelist_ips

# Whitelist ports
sudo nft list set inet portscan_defender whitelist_ports
```

### Manual Unblock (Emergency)

```bash
# Remove a single IP from both sets
sudo nft delete element inet portscan_defender temp_block { 203.0.113.45 }
sudo nft delete element inet portscan_defender perm_block { 203.0.113.45 }

# Flush all blocks (nuclear option)
sudo nft flush set inet portscan_defender temp_block
sudo nft flush set inet portscan_defender perm_block
```

---

## 🧠 How It Works

### Detection Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│ 1. nftables logs every new TCP connection to a non-         │
│    whitelisted port (rate-limited to prevent flooding).     │
├─────────────────────────────────────────────────────────────┤
│ 2. Every POLL_INTERVAL seconds, the daemon reads the last   │
│    DETECTION_WINDOW seconds of kernel log via journalctl.   │
├─────────────────────────────────────────────────────────────┤
│ 3. For each source IP, it computes:                         │
│      • unique destination ports                             │
│      • total connection attempts                            │
│      • SYN_RECEIVED count (via ss)                          │
├─────────────────────────────────────────────────────────────┤
│ 4. If any threshold is exceeded → trigger block.            │
├─────────────────────────────────────────────────────────────┤
│ 5. Escalation logic:                                        │
│      • 1st incident  → temporary block (auto-expires)       │
│      • 2nd incident  → permanent block (manual removal)     │
└─────────────────────────────────────────────────────────────┘
```

### Why nftables Sets?

nftables sets with `timeout` are **kernel-managed hash tables**:

- **O(1) lookup** on every incoming packet.
- **Auto-expiry** of temporary blocks without any daemon action.
- **Atomic operations** — no race conditions.
- **Persistent across daemon restarts** — blocks survive even if the service crashes.

This is significantly more efficient than alternatives like:

- `iptables -m recent` (linear search, per-rule)
- fail2ban with iptables rules (one rule per IP, slow with thousands of IPs)

### Anti-Flap Protection

If the same IP triggers detection repeatedly during an ongoing scan, the daemon won't escalate every cycle. A minimum of `DETECTION_WINDOW * 2` seconds must pass between two consecutive triggers for the same IP.

### State Pollution Defense

- `MAX_BLOCKED_IPS` caps the total number of blocks (default 1000).
- Whitelisted IPs are never analyzed.
- Invalid or reserved IPv4 addresses are skipped.
- Multicast / broadcast destinations are ignored.

---

## 🔐 Security Model

### systemd Hardening

The service runs with the following sandbox:

```ini
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
```

Verify with:

```bash
systemd-analyze security portscan-defender.service
```

### Why root?

The daemon needs:

- `CAP_NET_ADMIN` — to modify nftables sets.
- Read access to `journalctl -k` — kernel log.
- Read access to `ss` output — TCP state table.

The systemd sandbox restricts everything else.

### File Permissions

| Path | Mode | Owner |
|---|---|---|
| `/opt/portscan-defender/` | `755` | `root:root` |
| `/opt/portscan-defender/portscan-defender.sh` | `755` | `root:root` |
| `/opt/portscan-defender/*.conf`, `*.txt` | `644` | `root:root` |
| `/var/lib/portscan-defender/` | `750` | `root:root` |
| `/var/lib/portscan-defender/state.tsv` | `600` | `root:root` |
| `/var/log/portscan-defender/` | `750` | `root:root` |
| `/var/log/portscan-defender/defender.log` | `640` | `root:root` |

---

## 📊 Logs & Monitoring

### View Logs

```bash
# Live service log
sudo journalctl -u portscan-defender -f

# Application log file
sudo tail -f /var/log/portscan-defender/defender.log

# Kernel firewall log (with prefix PSD:)
sudo journalctl -k -f | grep "PSD:"
```

### Log Format

```
2026-09-21 12:15:33 [INFO]  PortScan Defender starting (PID 1443762)
2026-09-21 12:15:33 [INFO]  Loaded 12 whitelisted ports
2026-09-21 12:15:33 [INFO]  State loaded: 3 tracked IPs, 1 permanent
2026-09-21 12:15:34 [INFO]  Daemon ready. Poll interval: 5s.
2026-09-21 12:18:02 [ALERT] TEMPORARY BLOCK 203.0.113.45 | reason: port-diversity=28 rate=28 | duration: 3600s
2026-09-21 12:22:47 [ALERT] PERMANENT BLOCK 203.0.113.45 | reason: port-diversity=30 rate=30 | prior incidents: 1
2026-09-21 12:30:11 [WARN]  Manually unblocked 198.51.100.7
```

### Sample Output

```bash
$ sudo /opt/portscan-defender/portscan-defender.sh --status

=== PortScan Defender Status ===
Detection window:      10s
Port threshold:        15
Rate threshold:        25
SYN threshold:         5
Temp block duration:   3600s
Max blocked IPs:       1000
Tracked IPs:           3
Temporary blocks:      2
Permanent blocks:      1
Whitelisted ports:     12
nftables table:        inet portscan_defender
```

---

## 🔧 Troubleshooting

### Service fails with `203/EXEC`

**Cause:** CRLF line endings in the script (usually from Windows editors).

**Fix:**

```bash
sudo sed -i 's/\r$//' /opt/portscan-defender/portscan-defender.sh
sudo chmod 755 /opt/portscan-defender/portscan-defender.sh
sudo systemctl restart portscan-defender
```

Or use `dos2unix`:

```bash
sudo apt install dos2unix
sudo dos2unix /opt/portscan-defender/*
```

### Service fails with `status=1/FAILURE`

Check logs:

```bash
sudo journalctl -u portscan-defender -n 50 --no-pager
```

Common causes:

- nftables not installed → `apt install nftables`
- jq not installed → `apt install jq`
- Config syntax error → `bash -n /opt/portscan-defender/portscan-defender.conf`

### No blocks appearing

1. Check if nftables log rule is active:

   ```bash
   sudo nft list chain inet portscan_defender input
   ```

2. Check kernel log:

   ```bash
   sudo journalctl -k | grep "PSD:"
   ```

3. Verify the attacking IP is not in whitelist:

   ```bash
   sudo /opt/portscan-defender/portscan-defender.sh --status
   ```

4. Increase verbosity (in config):

   ```bash
   LOG_RATE_LIMIT=20000
   POLL_INTERVAL=2
   ```

### False positives blocking legitimate traffic

Add the source IP/network to `IP_WHITELIST` in the config, then:

```bash
sudo systemctl reload portscan-defender
sudo /opt/portscan-defender/portscan-defender.sh --unblock <false-positive-ip>
```

### Service restart loop

```bash
sudo systemctl stop portscan-defender
sudo systemctl reset-failed portscan-defender
sudo bash -x /opt/portscan-defender/portscan-defender.sh 2>&1 | tail -40
```

The `-x` trace shows exactly which line fails.

---

## 🗑️ Uninstallation

```bash
# 1) Stop and disable the service
sudo systemctl stop portscan-defender
sudo systemctl disable portscan-defender

# 2) Remove firewall table (removes all blocks)
sudo nft delete table inet portscan_defender

# 3) Remove files
sudo rm -rf /opt/portscan-defender
sudo rm -rf /var/lib/portscan-defender
sudo rm -rf /var/log/portscan-defender
sudo rm /etc/systemd/system/portscan-defender.service

# 4) Reload systemd
sudo systemctl daemon-reload
sudo systemctl reset-failed
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Commit changes: `git commit -m "Add my improvement"`
4. Push: `git push origin feature/my-improvement`
5. Open a Pull Request.

### Coding Guidelines

- **Line endings:** LF only (use `.gitattributes`).
- **ShellCheck:** All scripts must pass `shellcheck` with no warnings.
- **Bash 4.0+:** Use associative arrays, `mapfile`, `[[ ]]`, etc.
- **No external dependencies** beyond `nft`, `jq`, `journalctl`, `ss`.

Test with:

```bash
shellcheck portscan-defender.sh install.sh
bash -n portscan-defender.sh
```

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 HosseinHunTa

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

- Built on top of [nftables](https://nftables.org/) — the modern Linux firewall.
- Inspired by the simplicity of fail2ban, but designed for kernel-level performance.
- Thanks to the Debian and Ubuntu communities for excellent documentation.

---

<div align="center">

**⭐ If this project helped you, please give it a star! ⭐**

Made with ❤️ for the Linux security community.

</div>