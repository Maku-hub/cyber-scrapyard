# AutoRecon

> Multi-threaded network reconnaissance orchestrator that runs and organises a
> whole battery of enumeration tools automatically — built for CTFs, labs and
> exam environments like the OSCP.

- **Link:** https://github.com/Tib3rius/AutoRecon
- **Type:** open source
- **Platform:** cross-platform (Python, Linux-focused)

## Description

AutoRecon automates the tedious first hours of an engagement. Point it at one or
more targets and it launches port scans, then — based on the services it finds —
kicks off the appropriate follow-up tools (Nmap NSE scripts, web directory
brute-forcing, SMB/DNS/FTP enumeration and more) in parallel. Its real value is
organisation: results land in a tidy per-target directory tree with logs and
suggested manual commands, so you always know what was run and what to do next.
It's a wrapper around existing tools rather than a scanner itself, which makes it
a popular time-saver in OSCP-style multi-host scenarios.

## Installation

```bash
# Recommended: install with pipx (Python 3.8+)
pipx install git+https://github.com/Tib3rius/AutoRecon.git
```

```bash
# Install the underlying tools it orchestrates (Kali has most already)
sudo apt install nmap curl nikto gobuster feroxbuster smbclient dnsrecon
```

## Usage examples

```bash
# Full automated recon against a single target
autorecon 10.0.0.1

# Scan multiple targets at once
autorecon 10.0.0.1 10.0.0.2 scanme.example.com

# Read targets from a file
autorecon -t targets.txt

# Choose an output directory for the organised results
autorecon -o results/ 10.0.0.1

# Tune concurrency: max targets and max scans per target in parallel
autorecon --max-scans 20 --single-target 10.0.0.1

# Only run the quick port-scan profile (skip deeper service enumeration)
autorecon --port-scans top-100-ports 10.0.0.1
```

## Notes & references

- AutoRecon runs other tools, so install its dependencies first (Nmap, gobuster,
  feroxbuster, nikto, smbclient, dnsrecon, etc.) or scans will be skipped.
- Output is structured per target: `scans/` (tool output), `exploit/`, `loot/`
  and `report/` — read the `_commands.log` to see exactly what ran.
- Widely used for OSCP prep; it enumerates but does not exploit — you still do
  the analysis and manual follow-up it suggests.
- Some scans need root (SYN scans, certain NSE scripts); run with `sudo` when
  targeting privileged features.
