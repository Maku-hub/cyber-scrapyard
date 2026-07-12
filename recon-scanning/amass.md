# Amass

> OWASP's in-depth attack-surface mapper: subdomain enumeration and DNS
> reconnaissance that combines dozens of passive sources with active resolution.

- **Link:** https://github.com/owasp-amass/amass
- **Type:** open source
- **Platform:** cross-platform (Go binary; Docker image available)

## Description

Amass is the heavyweight of subdomain discovery. It pulls names from a large set
of passive sources (certificate transparency, search engines, APIs, DNS
databases) and can then actively resolve, brute-force, and permute them to build
a thorough picture of an organisation's external footprint. It also maps the
relationships between domains, ASNs, netblocks, and IPs, which makes it useful
for scoping an engagement, not just listing hosts. It's slower and more
comprehensive than lightweight tools like `subfinder` — reach for it when depth
matters.

## Installation

```bash
# Snap (kept current by the maintainers)
sudo snap install amass

# Or install with Go
go install -v github.com/owasp-amass/amass/v4/...@master

# Or run via Docker
docker run -v ~/.config/amass:/.config/amass caffix/amass enum -d example.com
```

## Usage examples

```bash
# Passive enumeration only — no packets to the target infrastructure
amass enum -passive -d example.com

# Active enumeration (resolves names, does more thorough discovery)
amass enum -d example.com

# Brute-force subdomains with a wordlist
amass enum -brute -w subdomains.txt -d example.com

# Enumerate several domains and save to an output file
amass enum -d example.com,example.org -o results.txt

# Query the local result graph database built by previous scans
amass db -d example.com -show

# Look up the netblocks and ASNs owned by an organisation
amass intel -org "Example Corp"

# Reverse-WHOIS to find related root domains
amass intel -whois -d example.com
```

## Notes & references

- Add API keys (Shodan, Censys, VirusTotal, SecurityTrails, etc.) in the config
  file to dramatically expand passive results:
  `~/.config/amass/config.yaml`.
- `-passive` sends nothing to the target — safe for stealthy recon; active mode
  performs DNS resolution and brute-forcing.
- Feed the results into resolvers/probers like [dnsx and
  httpx](subdomain-enumeration.md) to filter for live hosts.
- Docs & user guide: https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md
- Related: [Subdomain & DNS discovery](subdomain-enumeration.md), and the
  [OSINT](../osint/) category for passive sources.
