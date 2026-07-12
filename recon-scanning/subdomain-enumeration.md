# Subdomain & DNS Discovery

> A toolbox for finding subdomains and resolving DNS: fast passive collectors,
> DNS brute-forcers, and bulk resolvers you chain together into a pipeline.

- **Link:** see per-tool links below
- **Type:** open source
- **Platform:** cross-platform

## Description

Before you scan or fuzz anything, you need to know what hosts exist. Subdomain
enumeration finds the names an organisation exposes (`api.`, `dev.`, `vpn.`,
forgotten staging boxes), and DNS resolution turns those names into live,
scannable targets. No single tool is best at everything, so the practical
approach is a pipeline: collect names passively, brute-force for more, then
resolve and dedupe. The tools below cover each stage and share a common,
pipe-friendly line-per-host output format.

For the heavyweight, relationship-mapping alternative, see
[Amass](amass.md).

## Installation

```bash
# subfinder & dnsx (ProjectDiscovery, Go)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# assetfinder (Go)
go install github.com/tomnomnom/assetfinder@latest

# gobuster (Go) — or: sudo apt install gobuster
go install github.com/OJ/gobuster/v3@latest
```

## Usage examples

### subfinder — fast passive subdomain collection

```bash
# Passive enumeration from many public sources
subfinder -d example.com

# Silent output (just hostnames), saved to a file
subfinder -d example.com -silent -o subs.txt

# Enumerate a list of root domains
subfinder -dL roots.txt -silent
```

### assetfinder — quick passive names

```bash
# Find subdomains related to a domain (only those owned by the target)
assetfinder --subs-only example.com
```

### gobuster dns — DNS brute-forcing

Gobuster's `dns` mode brute-forces subdomains from a wordlist
(`gobuster dns -d example.com -w subdomains.txt`). It's documented in full on the
[gobuster](../web-app-security/gobuster.md) page alongside its `dir`/`vhost` modes.

### dnsx — bulk resolution & DNS queries

```bash
# Resolve a list of hosts, keep only the ones that exist
dnsx -l subs.txt -silent

# Pull specific record types
dnsx -l subs.txt -a -aaaa -cname -resp

# Full pipeline: collect -> resolve live hosts
subfinder -d example.com -silent | dnsx -silent -o live.txt
```

## Notes & references

- Add API keys to `~/.config/subfinder/provider-config.yaml` to widen passive
  results (VirusTotal, SecurityTrails, Shodan, etc.).
- Passive collection (subfinder, assetfinder) is quiet; DNS brute-forcing
  (gobuster) sends queries to resolvers.
- Watch for wildcard DNS, which makes every name "resolve" — `dnsx` can help
  filter these out.
- Next step: probe live hosts with `httpx`, then scan with [Nmap](nmap.md) or
  fuzz with web tools in [Web Application Security](../web-app-security/).
- Certificate Transparency is another rich, passive source of subdomains — see
  [Certificate Transparency](../osint/certificate-transparency.md).
- Tool homes: subfinder https://github.com/projectdiscovery/subfinder ·
  dnsx https://github.com/projectdiscovery/dnsx ·
  gobuster https://github.com/OJ/gobuster ·
  assetfinder https://github.com/tomnomnom/assetfinder
