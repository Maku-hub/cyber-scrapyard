# Nmap

> The industry-standard network scanner: host discovery, port scanning,
> service/version and OS fingerprinting, plus a scripting engine (NSE) that
> turns it into a light vulnerability scanner.

- **Link:** https://nmap.org
- **Type:** open source
- **Platform:** cross-platform (`zenmap` GUI, `ndiff` for diffing results)

## Description

Nmap is usually the first tool you run against a target. It tells you which
hosts are alive, which ports are open, what services and versions are behind
them, and — through the Nmap Scripting Engine (NSE) — can check for specific
misconfigurations and known vulnerabilities. It's fast enough for a single host
and scriptable enough for a lab full of them.

## Installation

```bash
sudo apt install nmap        # Debian/Kali/Ubuntu
```

## Usage examples

```bash
# Ping sweep — find live hosts without scanning ports
nmap -sn 192.168.1.0/24

# Service/version detection on open ports
nmap -sV 192.168.1.1

# OS detection
nmap -O 192.168.1.1

# Skip host discovery (useful when the target blocks ICMP)
nmap -Pn 192.168.1.1

# Aggressive scan: OS + version + default scripts + traceroute
nmap -A 192.168.1.1

# Full TCP port range, saving output in all formats
nmap -p- -oA fullscan 192.168.1.1

# Run the vulnerability-detection NSE scripts
nmap --script vuln 192.168.1.1

# Default safe scripts against a single port
nmap -sC -p 80 192.168.1.1
```

### Timing & evasion

```bash
# Timing templates: -T0 (paranoid) ... -T3 (default) ... -T5 (insane)
nmap -T4 192.168.1.1

# Fragment packets to slip past some IDS/IPS
nmap -f 192.168.1.0/24

# Spoof source port to look like DNS traffic (may bypass firewall rules)
nmap --source-port 53 192.168.1.0/24

# Decoy scan — mix your IP with random decoys
nmap -D RND:10 192.168.1.0/24
```

## Notes & references

- Output formats: `-oN` (normal), `-oX` (XML, great for importing into
  Metasploit via `db_import`), `-oG` (greppable), `-oA` (all three).
- NSE scripts live at https://nmap.org/nsedoc ; extra vuln scripts:
  https://github.com/scipag/vulscan
- For very large ranges, discover ports with [Masscan](masscan.md) first, then
  run `nmap -sV` only on the open ports.
- Timing/port-selection docs: https://nmap.org/book/performance-port-selection.html
