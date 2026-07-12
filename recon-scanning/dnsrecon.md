# DNSRecon

> Versatile DNS enumeration tool: standard record lookups, zone transfers,
> brute-force, reverse lookups, cache snooping and more from a single script.

- **Link:** https://github.com/darkoperator/dnsrecon
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

DNSRecon is a long-standing Python tool for pulling everything DNS can tell you
about a domain. It gathers standard records (A, AAAA, MX, NS, SOA, TXT, SRV),
attempts zone transfers against each name server, brute-forces subdomains from a
wordlist, performs reverse lookups over IP ranges, and can enumerate common SRV
records and check for wildcard resolution. It's a staple of the DNS phase of
recon and produces machine-readable output for feeding into other tooling.

## Installation

```bash
sudo apt install dnsrecon        # Debian/Kali/Ubuntu
```

```bash
# Or install from source with pip
pip install git+https://github.com/darkoperator/dnsrecon.git
```

## Usage examples

```bash
# Standard enumeration: pull all common records for a domain
dnsrecon -d example.com

# Attempt a zone transfer (AXFR) against the domain's name servers
dnsrecon -d example.com -t axfr

# Brute-force subdomains from a wordlist
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t brt

# Reverse lookup over an IP range
dnsrecon -r 192.168.1.0/24

# Enumerate common SRV records (useful for AD/service discovery)
dnsrecon -d example.com -t srv

# Save results as JSON for later parsing
dnsrecon -d example.com -j results.json
```

## Notes & references

- Scan types (`-t`): `std` (standard), `axfr` (zone transfer), `brt`
  (brute-force), `srv`, `rvl` (reverse) and more — combine as needed.
- A successful zone transfer (AXFR) hands you the entire zone; misconfigured
  name servers that allow it are a quick win worth always checking.
- Output formats: `-j` (JSON), `-x` (XML), `-c` (CSV) for pipelines and reports.
- Pairs well with [fierce](fierce.md) and [Amass](amass.md) for broader
  subdomain and attack-surface discovery.
