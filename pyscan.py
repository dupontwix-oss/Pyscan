#!/usr/bin/env python3
"""
██████╗ ██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝ ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║
██╔═══╝   ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║        ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝        ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
PyScan - Fast Port Scanner with Nmap Integration
Author: PyScan Project | Inspired by RustScan
"""

import asyncio
import socket
import ipaddress
import argparse
import sys
import os
import time
import random
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Dict
import concurrent.futures

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = RESET = ''
    class Style:
        BRIGHT = RESET_ALL = DIM = ''

# ─────────────────────────────────────────────
# TOP 1000 PORTS (Nmap standard)
# ─────────────────────────────────────────────
TOP_1000_PORTS = [
    1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,
    79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,
    139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,
    301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,
    465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,
    587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,
    711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,
    898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,
    1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,
    1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,
    1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,
    1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,
    1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,
    1110,1234,1433,1434,1494,1521,1720,1723,1755,1900,2000,2001,2049,
    2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,
    5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,
    8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,
    49155,49156,49157
]

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
██████╗ ██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝ ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║
██╔═══╝   ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║        ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝        ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.GREEN}  Fast Port Scanner + Nmap Integration{Style.RESET_ALL}
{Fore.YELLOW}  Inspired by RustScan | Python Edition{Style.RESET_ALL}
  {Fore.WHITE}github.com/pyscan | v1.0.0{Style.RESET_ALL}
"""

# ─────────────────────────────────────────────
# UTILS
# ─────────────────────────────────────────────

def print_info(msg: str):
    print(f"{Fore.CYAN}[~]{Style.RESET_ALL} {msg}")

def print_success(msg: str):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def print_error(msg: str):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

def print_warn(msg: str):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def print_scan(msg: str):
    print(f"{Fore.MAGENTA}[>]{Style.RESET_ALL} {msg}")

def resolve_host(host: str) -> Optional[str]:
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR notation to list of IPs."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [cidr]

def parse_addresses(addresses_input: str) -> List[str]:
    """Parse comma-delimited addresses, CIDRs, or file."""
    hosts = []
    # Check if it's a file
    if os.path.isfile(addresses_input):
        with open(addresses_input) as f:
            items = [line.strip() for line in f if line.strip()]
    else:
        items = [a.strip() for a in addresses_input.split(',')]

    for item in items:
        if '/' in item:
            hosts.extend(expand_cidr(item))
        else:
            hosts.append(item)
    return hosts

def parse_ports(ports_str: Optional[str], range_str: Optional[str],
                top: bool, exclude: Optional[str]) -> List[int]:
    """Parse ports from various inputs."""
    ports = set()

    if top:
        ports.update(TOP_1000_PORTS)
    if ports_str:
        if os.path.isfile(ports_str):
            with open(ports_str) as f:
                for line in f:
                    for p in line.strip().split(','):
                        try:
                            ports.add(int(p.strip()))
                        except ValueError:
                            pass
        else:
            for p in ports_str.split(','):
                try:
                    ports.add(int(p.strip()))
                except ValueError:
                    pass
    if range_str:
        try:
            start, end = map(int, range_str.split('-'))
            ports.update(range(start, end + 1))
        except ValueError:
            print_error(f"Invalid range format: {range_str}. Use start-end (e.g. 1-1000)")
            sys.exit(1)

    if not ports:
        # Default: common ports
        ports.update(TOP_1000_PORTS)

    # Exclude ports
    if exclude:
        for p in exclude.split(','):
            try:
                ports.discard(int(p.strip()))
            except ValueError:
                pass

    return sorted(list(ports))

def set_ulimit(value: int):
    """Set system file descriptor limit."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_NOFILE, (value, value))
        print_info(f"ulimit set to {value}")
    except Exception as e:
        print_warn(f"Could not set ulimit: {e}")

# ─────────────────────────────────────────────
# HOST DISCOVERY  (Phase 1 — like RustScan/Nmap -sn)
# ─────────────────────────────────────────────

def _tcp_ping(ip: str, port: int, timeout: float) -> bool:
    """TCP connect probe. Host is UP if open or connection refused (reset)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        err = s.connect_ex((ip, port))
        s.close()
        # 0=open  111/10061=refused (host up, port closed)
        return err in (0, 111, 10061)
    except OSError:
        return False

def _icmp_ping(ip: str, timeout: float) -> bool:
    """Raw ICMP echo. Requires root / CAP_NET_RAW."""
    import struct, select
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        # minimal ICMP echo packet
        data = b'pyscan'
        h    = struct.pack('bbHHh', 8, 0, 0, 1, 1)
        raw  = h + data
        csum = 0
        for i in range(0, len(raw), 2):
            csum += (raw[i] << 8) + (raw[i+1] if i+1 < len(raw) else 0)
        csum = ~((csum >> 16) + (csum & 0xffff)) & 0xffff
        h    = struct.pack('bbHHh', 8, 0, socket.htons(csum), 1, 1)
        sock.sendto(h + data, (ip, 0))
        r, _, _ = select.select([sock], [], [], timeout)
        sock.close()
        return bool(r)
    except (PermissionError, OSError):
        return False

def discover_hosts(ips: List[str], timeout_ms: int) -> List[str]:
    """
    Phase 1: Find which IPs are actually alive before port scanning.
    Uses ICMP ping (if root) + TCP probes on common ports.
    Same strategy as ‘nmap -sn’.
    """
    timeout = min(timeout_ms / 1000.0, 1.5)
    TCP_PORTS = [80, 443, 22, 445, 135, 8080, 53, 3389]

    # Check ICMP availability once
    can_icmp = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        can_icmp = True
    except PermissionError:
        pass

    def probe(ip: str) -> bool:
        if can_icmp and _icmp_ping(ip, timeout):
            return True
        for port in TCP_PORTS:
            if _tcp_ping(ip, port, timeout):
                return True
        return False

    alive = []
    max_w = min(256, len(ips))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_w) as pool:
        fmap = {pool.submit(probe, ip): ip for ip in ips}
        for fut in concurrent.futures.as_completed(fmap):
            ip = fmap[fut]
            try:
                if fut.result():
                    alive.append(ip)
            except Exception:
                pass

    return sorted(alive, key=lambda x: tuple(int(o) for o in x.split('.')))

# ─────────────────────────────────────────────
# ASYNC PORT SCANNER — FULLY PARALLEL (ALL HOSTS × ALL PORTS)
# ─────────────────────────────────────────────

import re as _re

async def scan_all_parallel(
    hosts: List[str],
    ports: List[int],
    timeout_ms: int,
    batch_size: int,
    tries: int,
    scan_order: str,
    greppable: bool,
) -> Dict[str, List[int]]:
    """
    Queue-based worker pool — exactly like RustScan's architecture.

    Instead of spawning 67k coroutines at once (which saturates the OS
    scheduler and makes every connection race against the clock before
    the semaphore even lets it through), we keep a fixed pool of
    `batch_size` concurrent workers that pull (host, port) jobs from
    a queue.  Open ports are printed the instant they are discovered.
    """

    if scan_order == 'random':
        ports = ports.copy()
        random.shuffle(ports)

    timeout_sec = timeout_ms / 1000.0
    results: Dict[str, List[int]] = {h: [] for h in hosts}

    # Build job queue
    queue: asyncio.Queue = asyncio.Queue()
    for h in hosts:
        for p in ports:
            await queue.put((h, p))

    total   = queue.qsize()
    completed = 0
    found     = 0
    progress_buf = ['']

    def _strip_ansi(s: str) -> str:
        return _re.sub(r'\x1b\[[0-9;]*m', '', s)

    def _clear():
        w = len(progress_buf[0])
        if w:
            print(f"\r{' ' * w}\r", end='', flush=True)

    def _print_open(host: str, port: int):
        _clear()
        if greppable:
            print(f"{host} -> {port}", flush=True)
        else:
            line = (
                f"{Fore.GREEN}[+]{Style.RESET_ALL} "
                f"{Fore.CYAN}{host}{Style.RESET_ALL}:"
                f"{Fore.GREEN}{Style.BRIGHT}{port}{Style.RESET_ALL}"
                f"  {Fore.GREEN}OPEN{Style.RESET_ALL}"
            )
            print(line, flush=True)

    def _redraw_progress():
        pct  = completed / total * 100 if total else 100
        line = (
            f"  {Fore.CYAN}Progress:{Style.RESET_ALL} "
            f"{completed}/{total} ({pct:.1f}%)  "
            f"{Fore.GREEN}Found: {found} open{Style.RESET_ALL}  "
            f"{Fore.YELLOW}Hosts: {len(hosts)}{Style.RESET_ALL}"
        )
        progress_buf[0] = _strip_ansi(line)
        print(f"\r{line}", end='', flush=True)

    async def tcp_probe(host: str, port: int) -> bool:
        """Single TCP connection attempt."""
        for _ in range(max(tries, 1)):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout_sec
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
        return False

    async def worker():
        """One worker: pull jobs from queue until empty."""
        nonlocal completed, found
        while True:
            try:
                host, port = queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            is_open = await tcp_probe(host, port)

            completed += 1
            if is_open:
                results[host].append(port)
                found += 1
                _print_open(host, port)

            if not greppable:
                _redraw_progress()

            queue.task_done()

    # Spawn exactly `batch_size` workers — no more, no less.
    # Each worker loops until the queue is drained.
    # This is the RustScan model: fixed pool, not one coroutine per task.
    num_workers = min(batch_size, total) if total else 1
    workers = [asyncio.create_task(worker()) for _ in range(num_workers)]
    await asyncio.gather(*workers)

    if not greppable:
        _clear()

    for h in results:
        results[h] = sorted(results[h])

    return results

# ─────────────────────────────────────────────
# UDP SCANNER
# ─────────────────────────────────────────────

def scan_port_udp(host: str, port: int, timeout: float) -> Tuple[int, bool]:
    """Scan a single UDP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout / 1000.0)
        sock.sendto(b'\x00' * 4, (host, port))
        try:
            data, _ = sock.recvfrom(1024)
            return port, True
        except socket.timeout:
            return port, False
        except ConnectionResetError:
            return port, False
        finally:
            sock.close()
    except Exception:
        return port, False

def scan_host_udp(host: str, ports: List[int], timeout: float, batch_size: int) -> List[int]:
    """Scan UDP ports using thread pool."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=batch_size) as executor:
        futures = {executor.submit(scan_port_udp, host, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)

# ─────────────────────────────────────────────
# NMAP INTEGRATION
# ─────────────────────────────────────────────

def run_nmap(host: str, open_ports: List[int], nmap_flags: str) -> Optional[Dict]:
    """
    Run Nmap with user flags.
    - Streams human-readable output to terminal in real time (exactly like bare nmap)
    - Simultaneously collects XML output (-oX) for report generation
    Returns parsed nmap data dict for the report, or None on failure.
    """
    if not open_ports:
        return None

    nmap_path = subprocess.run(['which', 'nmap'], capture_output=True, text=True).stdout.strip()
    if not nmap_path:
        print_warn("Nmap not found. Install it: sudo apt install nmap")
        return None

    ports_str = ','.join(map(str, open_ports))
    user_flags = nmap_flags.split() if nmap_flags else ['-sV']

    # We run nmap ONCE but with two output formats:
    #   -oN -   → normal human output streamed to stdout (what you see)
    #   -oX /tmp/pyscan_<host>.xml  → XML saved to file for report parsing
    import tempfile, os as _os
    xml_tmp = tempfile.NamedTemporaryFile(suffix='.xml', delete=False, prefix='pyscan_')
    xml_tmp.close()

    cmd = ['nmap'] + user_flags + ['-p', ports_str, '-oN', '-', '-oX', xml_tmp.name, host]

    print()
    print(f"{Fore.CYAN}{'─'*62}{Style.RESET_ALL}")
    print_info(f"Nmap: {Fore.YELLOW}{' '.join(['nmap'] + user_flags + ['-p', ports_str, host])}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─'*62}{Style.RESET_ALL}")
    print()

    nmap_data = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            print(line, end='', flush=True)
        proc.wait()

        # Parse the XML for report
        if _os.path.exists(xml_tmp.name):
            with open(xml_tmp.name, 'r', encoding='utf-8', errors='ignore') as xf:
                xml_content = xf.read()
            if xml_content.strip():
                nmap_data = parse_nmap_xml(xml_content, host)
    except KeyboardInterrupt:
        proc.terminate()
        print()
        print_warn("Nmap interrupted")
    except Exception as e:
        print_error(f"Nmap error: {e}")
    finally:
        try:
            _os.unlink(xml_tmp.name)
        except Exception:
            pass

    return nmap_data

def parse_nmap_xml(xml_output: str, host: str) -> Dict:
    """Parse Nmap XML output into structured data."""
    import xml.etree.ElementTree as ET
    result = {
        'host': host,
        'ports': [],
        'os': None,
        'raw_xml': xml_output
    }
    try:
        root = ET.fromstring(xml_output)
        for host_el in root.findall('.//host'):
            # OS detection
            osmatch = host_el.find('.//osmatch')
            if osmatch is not None:
                result['os'] = {
                    'name': osmatch.get('name', 'Unknown'),
                    'accuracy': osmatch.get('accuracy', '?')
                }
            # Port info
            for port_el in host_el.findall('.//port'):
                state_el = port_el.find('state')
                if state_el is not None and state_el.get('state') == 'open':
                    service_el = port_el.find('service')
                    port_info = {
                        'port': int(port_el.get('portid', 0)),
                        'protocol': port_el.get('protocol', 'tcp'),
                        'state': 'open',
                        'service': service_el.get('name', '') if service_el is not None else '',
                        'version': '',
                        'product': '',
                        'extrainfo': ''
                    }
                    if service_el is not None:
                        port_info['version'] = service_el.get('version', '')
                        port_info['product'] = service_el.get('product', '')
                        port_info['extrainfo'] = service_el.get('extrainfo', '')
                    # Scripts
                    scripts = []
                    for script in port_el.findall('script'):
                        scripts.append({
                            'id': script.get('id', ''),
                            'output': script.get('output', '')[:200]
                        })
                    port_info['scripts'] = scripts
                    result['ports'].append(port_info)
    except ET.ParseError as e:
        print_warn(f"Could not parse Nmap XML: {e}")
    return result

# ─────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_html_report(scan_results: List[Dict], output_path: str, scan_time: float):
    """Generate a professional HTML report."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total_hosts = len(scan_results)
    total_open = sum(len(r.get('open_ports', [])) for r in scan_results)

    # Build port rows
    all_rows = ''
    for result in scan_results:
        host = result['host']
        open_ports = result.get('open_ports', [])
        nmap_data = result.get('nmap', None)

        if not open_ports:
            all_rows += f'''
            <tr>
              <td><span class="host-badge">{host}</span></td>
              <td>—</td><td>—</td><td>—</td><td>—</td>
              <td><span class="badge badge-closed">No Open Ports</span></td>
            </tr>'''
            continue

        port_detail = {}
        if nmap_data:
            for p in nmap_data.get('ports', []):
                port_detail[p['port']] = p

        for port in open_ports:
            info = port_detail.get(port, {})
            service = info.get('service', 'unknown') or 'unknown'
            product = info.get('product', '')
            version = info.get('version', '')
            ver_str = f"{product} {version}".strip() or '—'
            proto = info.get('protocol', 'tcp')
            all_rows += f'''
            <tr>
              <td><span class="host-badge">{host}</span></td>
              <td class="port-num">{port}</td>
              <td><span class="proto-badge">{proto.upper()}</span></td>
              <td><span class="service-name">{service}</span></td>
              <td class="version-cell">{ver_str}</td>
              <td><span class="badge badge-open">OPEN</span></td>
            </tr>'''

    html = f'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PyScan Report — {timestamp}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;700;800&display=swap');

  :root {{
    --bg: #0a0c12;
    --bg2: #0f1219;
    --bg3: #151a24;
    --card: #131720;
    --border: #1e2536;
    --accent: #00d4ff;
    --accent2: #00ff88;
    --danger: #ff4757;
    --warn: #ffa502;
    --text: #e2e8f4;
    --text-dim: #6b7a99;
    --glow: rgba(0, 212, 255, 0.15);
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    min-height: 100vh;
    background-image:
      radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0, 212, 255, 0.08), transparent),
      repeating-linear-gradient(
        0deg,
        transparent,
        transparent 40px,
        rgba(30, 37, 54, 0.3) 40px,
        rgba(30, 37, 54, 0.3) 41px
      );
  }}

  .header {{
    padding: 3rem 2rem 2rem;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(180deg, rgba(0,212,255,0.05) 0%, transparent 100%);
    position: relative;
    overflow: hidden;
  }}

  .header::before {{
    content: 'PYSCAN';
    position: absolute;
    right: -1rem;
    top: -1rem;
    font-family: 'Syne', sans-serif;
    font-size: 10rem;
    font-weight: 800;
    color: rgba(0,212,255,0.03);
    pointer-events: none;
    user-select: none;
    letter-spacing: -0.05em;
  }}

  .logo {{
    font-family: 'Syne', sans-serif;
    font-size: 2.5rem;
    font-weight: 800;
    letter-spacing: -0.03em;
    color: var(--accent);
    text-shadow: 0 0 30px rgba(0,212,255,0.5);
    margin-bottom: 0.5rem;
  }}

  .logo span {{ color: var(--text-dim); }}

  .meta {{
    color: var(--text-dim);
    font-size: 0.8rem;
    margin-top: 0.5rem;
  }}

  .meta strong {{ color: var(--accent2); }}

  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    padding: 2rem;
    max-width: 1400px;
    margin: 0 auto;
  }}

  .stat-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
  }}

  .stat-card:hover {{ border-color: var(--accent); }}

  .stat-card::after {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
  }}

  .stat-label {{
    font-size: 0.7rem;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.5rem;
  }}

  .stat-value {{
    font-family: 'Syne', sans-serif;
    font-size: 2.5rem;
    font-weight: 800;
    color: var(--accent);
    line-height: 1;
  }}

  .stat-value.green {{ color: var(--accent2); }}
  .stat-value.red {{ color: var(--danger); }}

  .section {{
    max-width: 1400px;
    margin: 0 auto;
    padding: 0 2rem 3rem;
  }}

  .section-title {{
    font-family: 'Syne', sans-serif;
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.15em;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }}

  .section-title::after {{
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }}

  .table-wrap {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    overflow-x: auto;
  }}

  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }}

  thead th {{
    background: var(--bg3);
    padding: 1rem 1.25rem;
    text-align: left;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-dim);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }}

  tbody tr {{
    border-bottom: 1px solid rgba(30, 37, 54, 0.5);
    transition: background 0.15s;
  }}

  tbody tr:hover {{ background: rgba(0, 212, 255, 0.03); }}
  tbody tr:last-child {{ border-bottom: none; }}

  td {{
    padding: 0.85rem 1.25rem;
    vertical-align: middle;
  }}

  .host-badge {{
    background: rgba(0, 212, 255, 0.1);
    border: 1px solid rgba(0, 212, 255, 0.2);
    color: var(--accent);
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.8rem;
    white-space: nowrap;
  }}

  .port-num {{
    font-family: 'JetBrains Mono', monospace;
    color: var(--warn);
    font-weight: 600;
    font-size: 0.95rem;
  }}

  .proto-badge {{
    background: rgba(255, 165, 2, 0.1);
    border: 1px solid rgba(255, 165, 2, 0.2);
    color: var(--warn);
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 600;
  }}

  .service-name {{
    color: var(--accent2);
    font-weight: 600;
  }}

  .version-cell {{
    color: var(--text-dim);
    font-size: 0.8rem;
    max-width: 280px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }}

  .badge {{
    padding: 0.2rem 0.7rem;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}

  .badge-open {{
    background: rgba(0, 255, 136, 0.15);
    border: 1px solid rgba(0, 255, 136, 0.3);
    color: var(--accent2);
  }}

  .badge-closed {{
    background: rgba(255, 71, 87, 0.1);
    border: 1px solid rgba(255, 71, 87, 0.2);
    color: var(--danger);
  }}

  .footer {{
    text-align: center;
    padding: 2rem;
    color: var(--text-dim);
    font-size: 0.75rem;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
  }}

  .footer span {{ color: var(--accent); }}

  .search-bar {{
    display: flex;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }}

  .search-bar input {{
    flex: 1;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.65rem 1rem;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    outline: none;
    transition: border-color 0.2s;
  }}

  .search-bar input:focus {{ border-color: var(--accent); }}
  .search-bar input::placeholder {{ color: var(--text-dim); }}

  @keyframes fadeIn {{
    from {{ opacity: 0; transform: translateY(10px); }}
    to {{ opacity: 1; transform: translateY(0); }}
  }}

  .table-wrap {{ animation: fadeIn 0.5s ease; }}
  .stat-card {{ animation: fadeIn 0.4s ease; }}

  @media print {{
    body {{ background: white; color: black; }}
    .search-bar {{ display: none; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="logo">Py<span>Scan</span></div>
  <div style="color: var(--text-dim); font-size: 0.85rem; margin-top: 0.25rem;">
    Fast Port Scanner + Nmap Integration
  </div>
  <div class="meta">
    Generated: <strong>{timestamp}</strong> &nbsp;|&nbsp;
    Scan Duration: <strong>{scan_time:.2f}s</strong>
  </div>
</div>

<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-label">Hosts Scanned</div>
    <div class="stat-value">{total_hosts}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Open Ports Found</div>
    <div class="stat-value green">{total_open}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Scan Duration</div>
    <div class="stat-value" style="font-size:1.8rem">{scan_time:.2f}s</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Avg Ports/Host</div>
    <div class="stat-value" style="font-size:1.8rem">
      {f"{total_open/total_hosts:.1f}" if total_hosts > 0 else "0"}
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">Scan Results</div>

  <div class="search-bar">
    <input type="text" id="searchInput" placeholder="Filter by host, port, service, version..." onkeyup="filterTable()">
  </div>

  <div class="table-wrap">
    <table id="resultsTable">
      <thead>
        <tr>
          <th>Host</th>
          <th>Port</th>
          <th>Protocol</th>
          <th>Service</th>
          <th>Version / Product</th>
          <th>State</th>
        </tr>
      </thead>
      <tbody>
        {all_rows}
      </tbody>
    </table>
  </div>
</div>

<div class="footer">
  Generated by <span>PyScan</span> v1.0.0 &nbsp;|&nbsp; {timestamp} &nbsp;|&nbsp;
  Fast Port Scanner with Nmap Integration
</div>

<script>
function filterTable() {{
  const input = document.getElementById('searchInput').value.toLowerCase();
  const rows = document.getElementById('resultsTable').getElementsByTagName('tr');
  for (let i = 1; i < rows.length; i++) {{
    const text = rows[i].textContent.toLowerCase();
    rows[i].style.display = text.includes(input) ? '' : 'none';
  }}
}}
</script>

</body>
</html>'''

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print_success(f"HTML report saved: {output_path}")

def generate_pdf_report(scan_results: List[Dict], output_path: str, scan_time: float):
    """Generate a PDF report using ReportLab."""
    try:
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        print_error("reportlab not installed. Run: pip install reportlab")
        return

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total_hosts = len(scan_results)
    total_open = sum(len(r.get('open_ports', [])) for r in scan_results)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=landscape(A4),
        rightMargin=1.5*cm, leftMargin=1.5*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm
    )

    # Colors
    BG_DARK = colors.HexColor('#0a0c12')
    ACCENT = colors.HexColor('#00d4ff')
    ACCENT2 = colors.HexColor('#00ff88')
    DANGER = colors.HexColor('#ff4757')
    WARN = colors.HexColor('#ffa502')
    TEXT = colors.HexColor('#e2e8f4')
    TEXT_DIM = colors.HexColor('#6b7a99')
    CARD = colors.HexColor('#131720')
    BORDER = colors.HexColor('#1e2536')

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('title', fontName='Helvetica-Bold', fontSize=28,
                                  textColor=ACCENT, alignment=TA_LEFT, spaceAfter=4)
    sub_style = ParagraphStyle('sub', fontName='Helvetica', fontSize=10,
                                textColor=TEXT_DIM, alignment=TA_LEFT, spaceAfter=2)
    meta_style = ParagraphStyle('meta', fontName='Helvetica', fontSize=9,
                                 textColor=TEXT_DIM, spaceAfter=12)
    section_style = ParagraphStyle('section', fontName='Helvetica-Bold', fontSize=11,
                                    textColor=TEXT_DIM, spaceBefore=16, spaceAfter=8,
                                    textTransform='uppercase')

    story = []

    # Header
    story.append(Paragraph("PyScan", title_style))
    story.append(Paragraph("Fast Port Scanner + Nmap Integration", sub_style))
    story.append(Paragraph(f"Generated: {timestamp}  |  Duration: {scan_time:.2f}s", meta_style))
    story.append(HRFlowable(width='100%', thickness=1, color=BORDER, spaceAfter=12))

    # Stats table
    stats_data = [
        ['Hosts Scanned', 'Open Ports', 'Scan Duration', 'Avg Ports/Host'],
        [
            str(total_hosts),
            str(total_open),
            f"{scan_time:.2f}s",
            f"{(total_open/total_hosts):.1f}" if total_hosts > 0 else "0"
        ]
    ]
    stats_table = Table(stats_data, colWidths=[None]*4, hAlign='LEFT')
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), CARD),
        ('BACKGROUND', (0,1), (-1,1), BG_DARK),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 8),
        ('FONTNAME', (0,1), (-1,1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,1), (-1,1), 18),
        ('TEXTCOLOR', (0,0), (-1,0), TEXT_DIM),
        ('TEXTCOLOR', (0,1), (0,1), ACCENT),
        ('TEXTCOLOR', (1,1), (1,1), ACCENT2),
        ('TEXTCOLOR', (2,1), (2,1), WARN),
        ('TEXTCOLOR', (3,1), (3,1), ACCENT),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 14),
        ('RIGHTPADDING', (0,0), (-1,-1), 14),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('ROUNDEDCORNERS', [4]),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 14))

    # Results
    story.append(Paragraph("Scan Results", section_style))

    # Build data rows
    table_data = [['Host', 'Port', 'Protocol', 'Service', 'Version / Product', 'State']]

    for result in scan_results:
        host = result['host']
        open_ports = result.get('open_ports', [])
        nmap_data = result.get('nmap', None)

        if not open_ports:
            table_data.append([host, '—', '—', '—', '—', 'NONE'])
            continue

        port_detail = {}
        if nmap_data:
            for p in nmap_data.get('ports', []):
                port_detail[p['port']] = p

        for port in open_ports:
            info = port_detail.get(port, {})
            service = info.get('service', 'unknown') or 'unknown'
            product = info.get('product', '')
            version = info.get('version', '')
            ver_str = f"{product} {version}".strip() or '—'
            proto = info.get('protocol', 'tcp')
            table_data.append([host, str(port), proto.upper(), service, ver_str[:50], 'OPEN'])

    col_widths = [5*cm, 2.5*cm, 2.5*cm, 3.5*cm, 9*cm, 2.5*cm]
    results_table = Table(table_data, colWidths=col_widths, repeatRows=1)

    style = TableStyle([
        # Header
        ('BACKGROUND', (0,0), (-1,0), CARD),
        ('TEXTCOLOR', (0,0), (-1,0), TEXT_DIM),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 7.5),
        ('TOPPADDING', (0,0), (-1,0), 9),
        ('BOTTOMPADDING', (0,0), (-1,0), 9),
        # Data rows
        ('BACKGROUND', (0,1), (-1,-1), BG_DARK),
        ('TEXTCOLOR', (0,1), (-1,-1), TEXT),
        ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,1), (-1,-1), 8),
        ('TOPPADDING', (0,1), (-1,-1), 6),
        ('BOTTOMPADDING', (0,1), (-1,-1), 6),
        # Alternating rows
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG_DARK, CARD]),
        # Grid
        ('GRID', (0,0), (-1,-1), 0.3, BORDER),
        ('ALIGN', (1,0), (1,-1), 'CENTER'),
        ('ALIGN', (2,0), (2,-1), 'CENTER'),
        ('ALIGN', (5,0), (5,-1), 'CENTER'),
        # Color port column
        ('TEXTCOLOR', (1,1), (1,-1), WARN),
        ('FONTNAME', (1,1), (1,-1), 'Helvetica-Bold'),
        # Color service
        ('TEXTCOLOR', (3,1), (3,-1), ACCENT2),
        ('FONTNAME', (3,1), (3,-1), 'Helvetica-Bold'),
        # Color state
        ('TEXTCOLOR', (5,1), (5,-1), ACCENT2),
        ('FONTNAME', (5,1), (5,-1), 'Helvetica-Bold'),
        # Host color
        ('TEXTCOLOR', (0,1), (0,-1), ACCENT),
    ])
    results_table.setStyle(style)
    story.append(results_table)

    # Footer
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width='100%', thickness=0.5, color=BORDER))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"PyScan v1.0.0  |  Fast Port Scanner with Nmap Integration  |  {timestamp}",
        ParagraphStyle('footer', fontName='Helvetica', fontSize=7, textColor=TEXT_DIM, alignment=TA_CENTER)
    ))

    doc.build(story)
    print_success(f"PDF report saved: {output_path}")

# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# MAIN SCAN ORCHESTRATOR
# ─────────────────────────────────────────────

async def run_scan(args) -> List[Dict]:
    """Main scan routine — all hosts scanned in parallel."""
    start_time = time.time()

    # Parse targets
    raw_hosts = parse_addresses(args.addresses)

    # Exclude addresses
    if args.exclude_addresses:
        excluded = set(parse_addresses(args.exclude_addresses))
        raw_hosts = [h for h in raw_hosts if h not in excluded]

    # Parse ports
    ports = parse_ports(args.ports, args.range, args.top, args.exclude_ports)

    if not raw_hosts:
        print_error("No valid hosts to scan!")
        sys.exit(1)

    # ── PHASE 1: Resolve hostnames ──────────────────────────────────
    print_info("Resolving hosts...")
    host_map: Dict[str, str] = {}  # original -> ip
    for h in raw_hosts:
        ip = resolve_host(h)
        if ip is None:
            print_warn(f"Cannot resolve: {h} — skipping")
        else:
            host_map[h] = ip

    if not host_map:
        print_error("No resolvable hosts!")
        sys.exit(1)

    all_ips = list(host_map.values())

    # ── PHASE 2: Host discovery (ping sweep) ─────────────────────────
    # Only skip discovery for single-host or if explicitly disabled
    do_discovery = len(all_ips) > 1 and not getattr(args, 'skip_discovery', False)

    if do_discovery:
        print_info(f"Phase 1/2 — Host discovery across {Fore.CYAN}{len(all_ips)}{Style.RESET_ALL} address(es)...")
        alive_ips = discover_hosts(all_ips, timeout_ms=args.timeout)
        if not alive_ips:
            print_warn("No live hosts found. Try with -Pn to skip discovery, or check connectivity.")
            sys.exit(0)
        print_success(
            f"Found {Fore.GREEN}{Style.BRIGHT}{len(alive_ips)}{Style.RESET_ALL} live host(s): "
            + "  ".join(f"{Fore.CYAN}{ip}{Style.RESET_ALL}" for ip in alive_ips)
        )
        print()
    else:
        alive_ips = all_ips

    hosts_resolved = alive_ips

    # Build reverse map for display (ip -> original label)
    ip_to_orig_pre = {v: k for k, v in host_map.items()}

    # ── PHASE 3: Port scan only on live hosts ─────────────────────────
    print_info(f"Targets   : {Fore.CYAN}{len(hosts_resolved)}{Style.RESET_ALL} live host(s)")
    print_info(f"Ports     : {Fore.CYAN}{len(ports)}{Style.RESET_ALL} port(s)")
    print_info(f"Batch     : {Fore.CYAN}{args.batch_size}{Style.RESET_ALL} concurrent connections")
    print_info(f"Timeout   : {Fore.CYAN}{args.timeout}ms{Style.RESET_ALL}")
    print_info(f"Protocol  : {Fore.CYAN}{'UDP' if args.udp else 'TCP'}{Style.RESET_ALL}")
    print_info(f"Order     : {Fore.CYAN}{args.scan_order}{Style.RESET_ALL}")
    print()
    print_scan(f"{Fore.YELLOW}Phase 2/2 — Port scanning {len(hosts_resolved)} host(s) × {len(ports)} port(s)...{Style.RESET_ALL}")
    print()

    # ── RUN THE BIG PARALLEL SCAN ──────────────────────────────────
    if args.udp:
        # UDP: parallel via threads
        open_map: Dict[str, List[int]] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.batch_size) as pool:
            futures = {}
            for h, ip in host_map.items():
                for port in ports:
                    futures[pool.submit(scan_port_udp, ip, port, args.timeout)] = (h, ip, port)
            for fut in concurrent.futures.as_completed(futures):
                h, ip, port = futures[fut]
                _, p, is_open = fut.result() if len(fut.result()) == 3 else (*fut.result(), None)
                p_val, is_open_val = fut.result()
                if is_open_val:
                    open_map.setdefault(ip, []).append(p_val)
                    if args.greppable:
                        print(f"{ip} -> {p_val}")
                    else:
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.GREEN}{Style.BRIGHT}{p_val}{Style.RESET_ALL}  OPEN")
        for ip in open_map:
            open_map[ip] = sorted(open_map[ip])
    else:
        open_map = await scan_all_parallel(
            hosts=hosts_resolved,
            ports=ports,
            timeout_ms=args.timeout,
            batch_size=args.batch_size,
            tries=args.tries,
            scan_order=args.scan_order,
            greppable=args.greppable,
        )
    # ───────────────────────────────────────────────────────────────

    # Build results list + print summary per host
    all_results = []

    # Build reverse ip->original map
    ip_to_orig = ip_to_orig_pre

    total_open = sum(len(v) for v in open_map.values())

    if not args.greppable:
        print()
        print(f"{Fore.CYAN}{'─'*62}{Style.RESET_ALL}")
        print_success(
            f"Scan complete! "
            f"{Fore.GREEN}{Style.BRIGHT}{total_open}{Style.RESET_ALL} open port(s) "
            f"across {Fore.CYAN}{len(host_map)}{Style.RESET_ALL} host(s)"
        )
        print_info(f"Total time: {time.time() - start_time:.2f}s")
        print(f"{Fore.CYAN}{'─'*62}{Style.RESET_ALL}")
        print()

    # Per-host nmap + result assembly
    for ip in hosts_resolved:
        orig = ip_to_orig.get(ip, ip)
        open_ports = open_map.get(ip, [])

        if not args.greppable and open_ports:
            ports_str = '  '.join(
                f"{Fore.GREEN}{Style.BRIGHT}{p}{Style.RESET_ALL}" for p in open_ports
            )
            print_success(f"{Fore.CYAN}{orig}{Style.RESET_ALL} open: {ports_str}")

        result = {'host': orig, 'ip': ip, 'open_ports': open_ports, 'nmap': None}

        # Run Nmap only if user explicitly passed --nmap flags
        if not args.greppable and open_ports and args.nmap:
            nmap_data = run_nmap(ip, open_ports, args.nmap)
            if nmap_data:
                result['nmap'] = nmap_data

        all_results.append(result)

    total_time = time.time() - start_time

    # Generate reports
    if args.html_output:
        generate_html_report(all_results, args.html_output, total_time)

    if args.pdf_output:
        generate_pdf_report(all_results, args.pdf_output, total_time)

    if args.json_output:
        safe = []
        for r in all_results:
            s = {k: v for k, v in r.items() if k != 'nmap'}
            s['nmap'] = {k: v for k, v in (r.get('nmap') or {}).items() if k != 'raw_xml'}
            safe.append(s)
        with open(args.json_output, 'w') as f:
            json.dump(safe, f, indent=2)
        print_success(f"JSON saved: {args.json_output}")

    return all_results

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='pyscan',
        description='PyScan — Fast Port Scanner with Nmap Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pyscan -a 192.168.1.1
  pyscan -a 192.168.1.0/24 -p 80,443,8080
  pyscan -a 10.0.0.1-10 -r 1-1000 --html-output report.html
  pyscan -a targets.txt --top --pdf-output report.pdf
  pyscan -a 192.168.1.1 -p 80,443 -g
  pyscan -a 192.168.1.1 --udp -r 1-1024
        """
    )

    parser.add_argument('-a', '--addresses', required=True,
                        help='Comma-delimited list or file of CIDRs, IPs, or hosts')
    parser.add_argument('-p', '--ports',
                        help='Comma-separated ports (e.g. 80,443,8080)')
    parser.add_argument('-r', '--range',
                        help='Port range (e.g. 1-1000)')
    parser.add_argument('--top', action='store_true',
                        help='Use top 1000 ports')
    parser.add_argument('-e', '--exclude-ports',
                        help='Comma-separated ports to exclude')
    parser.add_argument('-x', '--exclude-addresses',
                        help='Comma-separated CIDRs/IPs to exclude')
    parser.add_argument('-b', '--batch-size', type=int, default=4500,
                        help='Concurrent connections batch size (default: 4500)')
    parser.add_argument('-t', '--timeout', type=int, default=1500,
                        help='Timeout in milliseconds (default: 1500)')
    parser.add_argument('--tries', type=int, default=1,
                        help='Number of attempts per port (default: 1)')
    parser.add_argument('-u', '--ulimit', type=int,
                        help='Set system file descriptor limit')
    parser.add_argument('--scan-order', choices=['serial', 'random'], default='serial',
                        help='Scan order: serial or random (default: serial)')
    parser.add_argument('--nmap', metavar='FLAGS', default=None,
                        help='Run nmap with YOUR flags on open ports. '
                             'Example: --nmap "-sV -sC" or --nmap "-A -O --script=vuln"')
    parser.add_argument('--udp', action='store_true',
                        help='UDP scan mode')
    parser.add_argument('-g', '--greppable', action='store_true',
                        help='Greppable output (no Nmap, ports only)')
    parser.add_argument('--no-banner', action='store_true',
                        help='Hide the banner')
    parser.add_argument('--resolver',
                        help='Comma-delimited DNS resolvers (file or list)')
    parser.add_argument('--accessible', action='store_true',
                        help='Accessible mode (screen reader friendly)')
    parser.add_argument('-Pn', '--skip-discovery', action='store_true',
                        help='Skip host discovery (treat all hosts as online, like nmap -Pn)')

    # Output
    out_group = parser.add_argument_group('Output Options')
    out_group.add_argument('--html-output', metavar='FILE',
                           help='Save HTML report to file')
    out_group.add_argument('--pdf-output', metavar='FILE',
                           help='Save PDF report to file')
    out_group.add_argument('--json-output', metavar='FILE',
                           help='Save JSON results to file')

    parser.add_argument('-V', '--version', action='version', version='PyScan v1.0.0')

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Show banner
    if not args.no_banner and not args.greppable:
        print(BANNER)

    # Set ulimit if requested
    if args.ulimit:
        set_ulimit(args.ulimit)

    # Validate batch size
    if args.batch_size > 65535:
        args.batch_size = 65535
    if args.batch_size < 1:
        args.batch_size = 1

    # Fix tries
    if args.tries < 1:
        args.tries = 1

    # Run
    try:
        results = asyncio.run(run_scan(args))

        # JSON output
        if args.json_output:
            safe_results = []
            for r in results:
                safe_r = {k: v for k, v in r.items() if k != 'nmap'}
                safe_r['nmap'] = r.get('nmap', {})
                if safe_r['nmap']:
                    safe_r['nmap'].pop('raw_xml', None)
                safe_results.append(safe_r)
            with open(args.json_output, 'w') as f:
                json.dump(safe_results, f, indent=2)
            print_success(f"JSON results saved: {args.json_output}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Scan interrupted by user")
        sys.exit(0)

if __name__ == '__main__':
    main()
