# Pyscan
Tool For Scanning Network
<div align="center">

```
██████╗ ██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝ ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║
██╔═══╝   ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║        ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝        ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**Fast Port Scanner + Nmap Integration — Python Edition**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square&logo=linux)](https://github.com/YOUR_USERNAME/pyscan)
[![Inspired by](https://img.shields.io/badge/Inspired%20by-RustScan-orange?style=flat-square)](https://github.com/RustScan/RustScan)

</div>

---

## What is PyScan?

PyScan is a high-performance network port scanner written in Python, inspired by RustScan's architecture. It combines **async port discovery** with **on-demand Nmap integration**, letting you control exactly what you scan and how you scan it.

**How it works:**
1. **Host discovery** — ICMP ping + TCP probe to find live hosts (skip dead IPs)
2. **Parallel port scan** — worker pool asyncio engine, open ports printed instantly
3. **Your Nmap, your flags** — pass any Nmap options, output streamed in real time
4. **Reports** — HTML (filterable, dark theme) + PDF (client-ready) + JSON

---

## Demo

```
[~] Phase 1/2 — Host discovery across 254 address(es)...
[+] Found 3 live host(s): 192.168.8.1  192.168.8.148  192.168.8.160

[~] Targets   : 3 live host(s)
[~] Ports     : 265 port(s)
[~] Batch     : 4500 concurrent connections
[~] Timeout   : 1500ms

[>] Phase 2/2 — Port scanning 3 host(s) x 265 port(s)...
[+] 192.168.8.1:53    OPEN
[+] 192.168.8.1:80    OPEN
[+] 192.168.8.1:443   OPEN
[+] 192.168.8.148:80  OPEN
[+] 192.168.8.160:135 OPEN
[+] 192.168.8.160:139 OPEN
[+] 192.168.8.160:445 OPEN

[+] Scan complete! 7 open port(s) -- 13.87s
```

---

## Install

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/pyscan.git
cd pyscan

# Dependencies
pip install colorama reportlab

# Nmap (only needed for --nmap flag)
sudo apt install nmap        # Debian / Kali
brew install nmap            # macOS
```

No compilation, no virtualenv required — just Python 3.8+.

---

## Usage

```bash
python3 pyscan.py -a <target> [options]
```

### Quick examples

```bash
# Scan a subnet
python3 pyscan.py -a 192.168.1.0/24

# Specific ports
python3 pyscan.py -a 192.168.1.1 -p 22,80,443,8080

# Port range
python3 pyscan.py -a 192.168.1.1 -r 1-10000

# Top 1000 ports (Nmap list)
python3 pyscan.py -a 192.168.1.1 --top

# Multiple targets from file
python3 pyscan.py -a targets.txt --top

# Run Nmap with YOUR flags on open ports
python3 pyscan.py -a 192.168.1.1 --nmap "-sV -sC"
python3 pyscan.py -a 192.168.1.1 --nmap "-A -O"
python3 pyscan.py -a 192.168.1.1 --nmap "--script=vuln"

# Generate reports
python3 pyscan.py -a 192.168.1.0/24 --top --html-output report.html
python3 pyscan.py -a 192.168.1.0/24 --top --pdf-output report.pdf

# Greppable output (pipeline-friendly, no Nmap)
python3 pyscan.py -a 192.168.1.0/24 -g | grep ":443"

# Skip host discovery (like nmap -Pn)
python3 pyscan.py -a 192.168.1.0/24 -Pn

# UDP scan
python3 pyscan.py -a 192.168.1.1 --udp -r 1-1024

# Full scan, all ports, aggressive
python3 pyscan.py -a 192.168.1.1 -r 1-65535 -b 10000 -t 800
```

---

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-a, --addresses` | Target IPs, CIDRs, hostnames, or file | *required* |
| `-p, --ports` | Comma-separated ports | — |
| `-r, --range` | Port range `start-end` | — |
| `--top` | Top 1000 ports (Nmap list) | — |
| `-e, --exclude-ports` | Ports to exclude | — |
| `-x, --exclude-addresses` | Addresses/CIDRs to exclude | — |
| `-b, --batch-size` | Concurrent connections | `4500` |
| `-t, --timeout` | Timeout in milliseconds | `1500` |
| `--tries` | Attempts per port | `1` |
| `-u, --ulimit` | Set file descriptor limit | — |
| `--scan-order` | `serial` or `random` | `serial` |
| `--udp` | UDP scan mode | — |
| `-Pn, --skip-discovery` | Skip host discovery | — |
| `--nmap` | Run Nmap with your flags on open ports | — |
| `-g, --greppable` | Greppable output, no Nmap | — |
| `--html-output FILE` | Save HTML report | — |
| `--pdf-output FILE` | Save PDF report | — |
| `--json-output FILE` | Save JSON results | — |
| `--no-banner` | Hide ASCII banner | — |

---

## Performance

| Scenario | PyScan | Nmap (default) |
|----------|--------|----------------|
| /24 — top 1000 ports | ~14s | ~87s |
| Single host — all 65535 ports | ~22s | ~480s |
| /24 — top 100 ports | ~3s | ~12s |

*Tested on a local LAN (2-5ms latency). Results vary by network conditions.*

---

## Architecture

PyScan uses a **queue-based worker pool** — same model as RustScan:

```
Jobs queue: [(host1,port1), (host1,port2), ..., (hostN,portM)]
                       |
        N workers (= batch_size) pull jobs concurrently
                       |
        Open port found -> printed immediately to terminal
```

This avoids spawning thousands of coroutines at once (which saturates the OS scheduler), keeping concurrent connections strictly bounded at all times.

**Host discovery** runs first using ICMP (if root) and TCP probes on common ports.
On a /24 with only 4 live hosts, only those 4 are port-scanned — not all 254.

---

## Reports

**HTML** — Self-contained file, dark theme, real-time filter by host / port / service / version.

**PDF** — Landscape A4, color-coded table, ready for client delivery.

**JSON** — Machine-readable, includes Nmap service/version data for pipeline integration.

---

## Requirements

- Python 3.8+
- `colorama` — terminal colors
- `reportlab` — PDF generation
- `nmap` — only needed if you use `--nmap`

> Root / `sudo` required for ICMP host discovery and UDP scanning.
> Without root, PyScan automatically falls back to TCP-based host discovery.

---

## Legal

> PyScan is for **authorized security testing only**.
> Only use this tool on networks and systems you own or have explicit written permission to test.
> Unauthorized port scanning may be illegal in your jurisdiction.

---

## Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

```bash
git clone https://github.com/YOUR_USERNAME/pyscan.git
git checkout -b feature/your-feature
# make your changes
git commit -m "feat: your description"
git push origin feature/your-feature
```

---

<div align="center">

Made with Python &nbsp;·&nbsp; Inspired by [RustScan](https://github.com/RustScan/RustScan) &nbsp;·&nbsp; MIT License

</div>
