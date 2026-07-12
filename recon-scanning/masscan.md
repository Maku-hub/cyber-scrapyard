# Masscan

> An asynchronous TCP port scanner that can scan the entire IPv4 internet in
> minutes. Think of it as a "rewritten Nmap" optimized purely for speed.

- **Link:** https://github.com/robertdavidgraham/masscan
- **Type:** open source
- **Platform:** Linux, Windows, macOS

## Description

Masscan trades Nmap's depth for raw speed: it transmits packets asynchronously
at a configurable rate, so it can sweep huge address ranges very quickly. It
does *not* do service/version detection well — the usual pattern is to use
Masscan to find open ports across a wide range, then hand those ports to
[Nmap](nmap.md) for detailed fingerprinting.

## Installation

```bash
sudo apt install masscan
```

## Usage examples

```bash
# Scan common web/SSH ports across a /24 at 1000 packets/sec
masscan -p80,443,22 10.77.14.0/24 --rate=1000

# Full port range across a /8 at high speed (lab/demo)
masscan 10.0.0.0/8 -p0-65535 --rate=10000

# Randomize host order to spread load
masscan -p80,443 10.0.0.0/8 --rate=1000 --randomize-hosts

# Output XML for import into Metasploit
masscan -Pn 10.10.0.0/24 -oX masscan.xml --rate=2000
```

## Notes & references

- **Rate matters:** scanning too fast causes dropped packets and false
  negatives/positives. Start conservative on unfamiliar networks.
- Import into Metasploit: `db_import masscan.xml`, then `services -u`.
- Masscan uses its own TCP/IP stack, so it can conflict with the OS stack —
  running from a dedicated interface or firewall exclusion is common.
