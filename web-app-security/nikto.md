# Nikto

> A classic web server scanner: quickly flags dangerous files, outdated
> software, and common misconfigurations. Noisy but fast for a first pass.

- **Link:** https://github.com/sullo/nikto
- **Type:** open source
- **Platform:** cross-platform (Perl)

## Description

Nikto performs comprehensive tests against a web server, checking for thousands
of potentially dangerous files/CGIs, outdated server versions, and
version-specific problems and misconfigurations. It's not stealthy — it fires a
lot of requests and shows up in logs immediately — but it's a fast, low-effort
way to surface obvious issues early in web reconnaissance.

## Installation

```bash
# Debian/Kali package
sudo apt install nikto

# Or clone from source
git clone https://github.com/sullo/nikto.git
```

## Usage examples

```bash
# Scan a host (comprehensive check for dangerous files & outdated software)
nikto -h networkchuck.coffee

# Scan a specific URL / port over HTTPS
nikto -h https://target.example.com -p 443

# Save output to a file (HTML report)
nikto -h target.example.com -o report.html -Format htm

# Tune which test categories run (e.g. 1=interesting files, 4=injection)
nikto -h target.example.com -Tuning 1234

# Pass through a proxy (e.g. route via Burp for inspection)
nikto -h target.example.com -useproxy http://127.0.0.1:8080
```

## Notes & references

- Very noisy — it will trip IDS/WAF and fill logs. Fine for authorized labs and
  quick triage, not for stealthy engagements.
- Findings often need manual verification; treat it as a lead generator, then
  confirm with [Burp Suite](burp-suite.md) or curl.
- For template-based, lower-noise checks use [Nuclei](nuclei.md).
- Docs: https://github.com/sullo/nikto/wiki
