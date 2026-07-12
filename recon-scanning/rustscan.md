# RustScan

> A modern, very fast port scanner that finds open ports in seconds and then
> automatically pipes them into Nmap for detailed enumeration.

- **Link:** https://github.com/RustScan/RustScan
- **Type:** open source
- **Platform:** cross-platform (also distributed as a Docker image)

## Description

RustScan fills the gap between Masscan's speed and Nmap's depth: it scans all
65,535 ports extremely quickly, then automatically launches Nmap against only
the ports it found open. You get fast discovery *and* rich fingerprinting in a
single command, which makes it a convenient default for single-host recon.

## Installation

```bash
# Docker (recommended for a clean, up-to-date install)
docker run -it --rm --name rustscan rustscan/rustscan:latest

# Or download a release binary / .deb from the GitHub releases page
```

## Usage examples

```bash
# Scan all ports, then hand the open ones to Nmap for -A
rustscan -a 192.168.1.1 -- -A

# Scan a range with a custom batch size (tune for speed vs. reliability)
rustscan -a 10.0.0.0/24 -b 1500

# Pass any Nmap flags after the `--`
rustscan -a 192.168.1.1 -- -sC -sV -oN scan.txt
```

## Notes & references

- Everything after `--` is passed straight through to Nmap.
- On flaky or rate-limited networks, lower the batch size (`-b`) to reduce
  false negatives.
- Great as a first pass on a single host; for large ranges,
  [Masscan](masscan.md) still wins on raw throughput.
