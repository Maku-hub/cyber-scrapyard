# naabu

> Fast, reliable port scanner written in Go — SYN/CONNECT scans built for speed
> and clean piping into the rest of a recon toolchain.

- **Link:** https://github.com/projectdiscovery/naabu
- **Type:** open source
- **Platform:** cross-platform (Go)

## Description

naabu (from ProjectDiscovery) is a lightweight port scanner focused on doing one
thing quickly: enumerate open ports on a host or list of hosts. It supports SYN
and CONNECT scans, host discovery, and a simple stdin/stdout design that lets you
chain it with [subfinder](https://github.com/projectdiscovery/subfinder),
[httpx](httpx.md) and [Nmap](nmap.md). A common pattern is to use naabu for the
fast open-port sweep, then hand those ports to Nmap for deep service/version
detection.

## Installation

```bash
# Install with Go (requires Go 1.21+); libpcap needed for SYN scans
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

## Usage examples

```bash
# Scan the top 100 ports on a single host
naabu -host example.com -top-ports 100

# Scan a specific port range
naabu -host example.com -p 1-1000

# Scan every TCP port
naabu -host example.com -p -

# Scan a list of hosts from a file
naabu -list hosts.txt

# SYN scan (faster, needs root/CAP_NET_RAW)
sudo naabu -host example.com -scan-type s

# Pipe subfinder results into naabu, then into httpx
subfinder -d example.com -silent | naabu -silent | httpx -silent

# Hand naabu's open ports straight to Nmap for service detection
naabu -host example.com -nmap-cli 'nmap -sV -sC'

# Output results as JSON
naabu -host example.com -json -o ports.json
```

## Notes & references

- SYN scans (`-scan-type s`) require root privileges and libpcap; CONNECT scans
  (`-scan-type c`) work without elevated rights but are slower.
- Tune throughput with `-rate` (packets per second) and `-c` (concurrency); back
  off on production or shared networks.
- `-nmap-cli` runs Nmap automatically against the discovered open ports, giving
  you speed plus depth in one command.
- Docs: https://docs.projectdiscovery.io/tools/naabu
