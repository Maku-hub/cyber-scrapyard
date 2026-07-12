# theHarvester

> A fast, focused e-mail, subdomain, and host gatherer — classic first step for
> mapping an organisation's public footprint from open sources.

- **Link:** https://github.com/laramies/theHarvester
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

theHarvester does one job well: it collects emails, names, subdomains, IPs, and
URLs about a domain from a wide range of public sources (search engines,
certificate transparency, PGP key servers, Shodan, and more). It's lightweight,
scriptable, and ships with Kali, which makes it a natural opening move in the
recon phase — build a list of employee emails and hostnames before deciding
where to dig deeper.

## Installation

```bash
# Debian/Kali (usually preinstalled)
sudo apt install theharvester

# Or with pipx from source
pipx install git+https://github.com/laramies/theHarvester.git
```

## Usage examples

```bash
# Gather from all supported sources (limit 500 results)
theHarvester -d example.com -b all -l 500

# Gather from a single source (e.g. crt.sh certificate transparency)
theHarvester -d example.com -b crtsh

# Limit results and save an HTML/JSON report
theHarvester -d example.com -b bing -l 200 -f report

# Enable DNS brute-forcing of subdomains
theHarvester -d example.com -b all -c

# Take screenshots of discovered hosts
theHarvester -d example.com -b all --screenshot screens/
```

## Notes & references

- Some sources need API keys — add them to `api-keys.yaml` (Shodan, Hunter,
  SecurityTrails, etc.).
- `-b all` runs every source but is noisier and slower; pick specific `-b`
  sources for targeted, quieter runs.
- Pairs naturally with [subdomain tooling](../recon-scanning/subdomain-enumeration.md)
  and [recon-ng](recon-ng.md) for deeper enumeration; emails feed
  [people & username OSINT](people-username-osint.md).
- Docs: https://github.com/laramies/theHarvester/wiki
