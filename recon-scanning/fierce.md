# fierce

> DNS reconnaissance tool for locating non-contiguous IP space and hostnames
> against a domain — a quick way to find likely subdomains and adjacent hosts.

- **Link:** https://github.com/mschwager/fierce
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

fierce is a focused DNS recon tool that helps you find the targets a domain
actually owns. It first tries a zone transfer, and if that fails it brute-forces
subdomains from a wordlist, then scans nearby IPs around any hosts it finds to
discover non-contiguous address space that belongs to the same target. It's not a
scanner in the port sense — it's a locator, meant to feed the hostnames and IPs
it uncovers into tools like [Nmap](nmap.md) and [httpx](httpx.md).

## Installation

```bash
# Install with pipx (recommended, keeps it isolated)
pipx install fierce
```

```bash
# Or install with pip
pip install fierce
```

## Usage examples

```bash
# Basic recon: zone transfer attempt then default subdomain brute-force
fierce --domain example.com

# Use a custom subdomain wordlist
fierce --domain example.com --subdomain-file wordlist.txt

# Widen the nearby-IP scan around discovered hosts
fierce --domain example.com --wide

# Search a range of IPs around each found host
fierce --domain example.com --search example,corp

# Point at a specific DNS server for lookups
fierce --domain example.com --dns-servers 8.8.8.8

# Add a delay between lookups to stay quiet
fierce --domain example.com --delay 2
```

## Notes & references

- This is the modern Python 3 rewrite by mschwager; the original was a Perl
  script bundled with older Kali releases — flags differ, so check `fierce -h`.
- `--wide` scans the whole /24 around each discovered host, which is noisier but
  surfaces adjacent infrastructure.
- Great as a first-pass subdomain finder; combine with [DNSRecon](dnsrecon.md)
  and [Amass](amass.md) for fuller coverage.
