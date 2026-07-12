# Linux

> A reference of useful Linux commands for networking, reconnaissance, file/user
> analysis, and permission handling — plus notes on the privilege-escalation
> primitives every administrator should recognise.
>
> ⚠️ **For authorized and educational use only.** These are for systems you own
> or administer and for authorized lab work.

Handy companion: <https://explainshell.com/> breaks any command line into its
parts.

## Connectivity & diagnostics

```bash
# Basic reachability / latency check
ping 192.168.0.1

# Larger packets — probe how the path handles fragmentation
ping -s 1300 172.18.0.11

# Flood with large packets (stress/DoS resilience testing only, in a lab)
ping -s 1300 -f 172.18.0.11

# Live per-interface bandwidth usage — spot anomalies
iftop

# Tunnel traffic inside ICMP echo (bypass restrictive networks / covert channel)
ptunnel

# Force pending disk writes to flush (safe before removing media)
sync
```

## DNS & host reconnaissance

```bash
# Domain registration / ownership info
whois microsoft.com

# Resolve a host
host microsoft.com

# A record (short) and MX records
dig a +short microsoft.com
dig mx microsoft.com
```

> **Recon tooling lives in its own categories.** Web, subdomain, port-scanning
> and exploit-research tools are documented where they belong — this page stays
> about Linux itself:
> [Reconnaissance & Scanning](../recon-scanning/) (Nmap, Masscan, RustScan),
> [Web Application Security](../web-app-security/) (nikto, gobuster, ffuf,
> sqlmap, wpscan), [OSINT](../osint/) + [Amass](../recon-scanning/amass.md), and
> [searchsploit](../exploitation-c2/searchsploit.md).

`curl` stays useful for quick manual checks from a Linux box:

```bash
# GET a URL and show full response headers
curl -i https://example.com

# Send a custom auth header (e.g. API testing)
curl -i https://example.com -H 'X-API-TOKEN: <api-token>'
```

## Remote access & pivoting

```bash
# Connect over SSH
ssh user@192.168.1.1

# Run a single remote command
ssh user@remote_host 'command_to_run'

# Dynamic SOCKS proxy through the target (-D), compressed (-C), quiet (-q),
# no remote command (-N) — used for pivoting / routing tools through a host
ssh -D 1337 -C -q -N root@172.234.88.97
```

## Users, files & processes

```bash
# View / delete the kernel ARP cache
arp -a
arp -d *

# Which commands can I run as root
sudo -l

# Show info about an executable found in PATH
type -a pwd

# Process ID by name, background jobs, reset a broken terminal
pgrep passwd
jobs
reset

# What devices were plugged into the machine (from logs)
grep SerialNumber /var/log/syslog
```

### Analysing `/etc/passwd`

```bash
# Count login shells, list usernames, sort UIDs, show the highest UIDs
grep bash passwd | wc -l
cut -d : -f 1 passwd
cut -d : -f 3 passwd | sort -n
cut -d : -f 3 passwd | sort -n | tail -n 3
wc -l passwd
```

## Network configuration

```bash
# Edit interface config and restart networking
nano /etc/network/interfaces
systemctl restart network.service

# DNS resolver configuration
nano /etc/resolv.conf
```

## Privilege escalation primitives (defensive awareness)

Recognising these misconfigurations is key to hardening a host.

```bash
# A setuid-root /bin/bash launched with -p keeps root's effective UID/GID.
# The classic mistake that enables this:
sudo chmod +s /bin/bash   # sets the setuid bit — do NOT do this on real systems
/bin/bash -p

# Writable sensitive files (e.g. group membership) are another escalation vector
sudo nano /etc/group
```

## Security testing

Tools in this repo for assessing a Linux host:

- **Local privilege escalation** — [LinPEAS](../post-exploitation/linpeas-winpeas.md),
  [privilege-escalation techniques](../post-exploitation/privilege-escalation.md),
  [pspy](../post-exploitation/pspy.md).
- **Config hardening & compliance** — [Lynis](../vulnerability-scanners/lynis.md),
  [OpenSCAP](../vulnerability-scanners/openscap.md).
- **Vuln scanning** — [OpenVAS](../vulnerability-scanners/openvas-greenbone.md) or
  [Nessus](../vulnerability-scanners/nessus.md).
- **End-to-end** — the [Linux Server Assessment](../scenarios/linux-server-assessment.md) scenario.

## Notes & references

- Privilege-escalation checklist:
  <https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/>
- For automated checks see LinPEAS in
  [Post-Exploitation & Privilege Escalation](../post-exploitation/).
- See [Windows](windows.md) for the equivalent Windows reference and
  [Recon Methodology](../methodology/recon-methodology.md) for how these fit into
  a workflow.
