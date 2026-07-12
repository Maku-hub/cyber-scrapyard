# ike-scan

> Discover and fingerprint IPsec VPN gateways by probing the IKE service
> (UDP/500) — identify implementations and pull PSK material for offline cracking.

- **Link:** https://github.com/royhills/ike-scan
- **Type:** open source
- **Platform:** Linux / Unix-like

## Description

ike-scan sends IKE (Internet Key Exchange) probes to VPN endpoints and analyzes
the responses to find live gateways, determine which transforms they accept, and
fingerprint the vendor implementation. In aggressive mode it can capture the
PSK hash, which can then be cracked offline. It's a niche but valuable tool when
a target exposes IPsec VPN services. Authorized testing only.

## Installation

```bash
sudo apt install ike-scan    # Debian/Kali/Ubuntu
```

## Usage examples

```bash
# Basic scan: is there an IKE service on this gateway? (UDP/500)
ike-scan 10.0.0.1

# Show the vendor fingerprint / backoff pattern to identify the implementation
ike-scan --showbackoff 10.0.0.1

# Aggressive mode with a group/ID name; --pskcrack writes the captured PSK hash
ike-scan --aggressive --id=vpngroup --pskcrack=psk.txt 10.0.0.1

# Scan a range for IKE endpoints
ike-scan 10.0.0.0/24
```

## Notes & references

- Aggressive mode (`-A`) can expose a crackable PSK hash; feed the
  `--pskcrack` output to `psk-crack` or [Hashcat](../password-cracking/hashcat.md)
  for offline recovery.
- IKE runs on **UDP/500** (and UDP/4500 for NAT-T); results complement an
  [Nmap](../recon-scanning/nmap.md) `-sU -p 500` scan.
- Man page & options: https://github.com/royhills/ike-scan/wiki
