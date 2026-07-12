# Nuclei

> Template-based vulnerability scanner from ProjectDiscovery — fast, YAML-driven
> checks for known CVEs, misconfigurations, and exposures across many hosts.

- **Link:** https://github.com/projectdiscovery/nuclei
- **Type:** open source
- **Platform:** cross-platform (Go)

## Description

Nuclei runs community-maintained **templates** (simple YAML files describing a
request and a match condition) against one or many targets. Instead of a
monolithic scanner, you get thousands of precise checks — known CVEs, default
credentials, exposed panels, misconfigurations, takeovers — that you can filter
by severity, tag, or technology. Its speed and low false-positive rate make it a
staple for bug bounty and large-scale attack-surface scanning.

## Installation

```bash
# Install with Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or download a release binary
# https://github.com/projectdiscovery/nuclei/releases
```

## Usage examples

```bash
# Update the template collection (do this first, and often)
nuclei -update-templates

# Scan a single target with all default templates
nuclei -u https://target.example.com

# Scan a list of hosts from a file
nuclei -l hosts.txt

# Only run high/critical severity templates
nuclei -u https://target.example.com -severity high,critical

# Filter by tag (e.g. only CVEs) and save findings
nuclei -u https://target.example.com -tags cve -o findings.txt

# Run a specific template or template directory
nuclei -u https://target.example.com -t http/exposures/

# Pipe in live hosts from other ProjectDiscovery tools
subfinder -d target.example.com | httpx | nuclei -severity medium,high
```

## Notes & references

- Templates live at https://github.com/projectdiscovery/nuclei-templates — keep
  them updated; you can also write your own YAML checks.
- Combines cleanly with the ProjectDiscovery stack (`subfinder`, `httpx`,
  `naabu`) — see [../recon-scanning/](../recon-scanning/).
- Tune with `-rl` (rate limit) and `-c` (concurrency) to stay polite / avoid WAF
  blocks. Authorized targets only.
- Docs: https://docs.projectdiscovery.io/tools/nuclei
