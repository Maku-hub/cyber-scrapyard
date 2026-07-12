# Katana

> A fast, modern web crawler from ProjectDiscovery that maps an app's endpoints
> — including JavaScript-rendered ones — to feed the rest of your toolchain.

- **Link:** https://github.com/projectdiscovery/katana
- **Type:** open source
- **Platform:** cross-platform (Go)

## Description

Katana crawls a target and produces a clean list of URLs, endpoints, and
parameters. It has two modes: a fast standard HTTP crawler and a headless mode
that drives a real browser to catch links only reachable after JavaScript runs.
It can parse JS files for endpoints, scope crawls to a domain, and stream results
to stdout — which makes it the natural front end of a pipeline that hands URLs to
[ffuf](ffuf.md), [Nuclei](nuclei.md), [dalfox](dalfox.md), or [Arjun](arjun.md).

## Installation

```bash
# Install the latest release with the Go toolchain
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Usage examples

```bash
# Crawl a single target and print discovered URLs
katana -u https://target.example.com

# Headless crawl to capture JavaScript-rendered endpoints
katana -u https://target.example.com -headless

# Control crawl depth
katana -u https://target.example.com -depth 3

# Also parse and crawl endpoints found inside JavaScript files
katana -u https://target.example.com -jc

# Keep the crawl within a set of scopes/domains
katana -u https://target.example.com -crawl-scope ".example.com"

# Feed crawled URLs straight into nuclei for scanning
katana -u https://target.example.com -silent | nuclei -silent

# Save results to a file for later fuzzing with ffuf
katana -u https://target.example.com -o urls.txt
```

## Notes & references

- Part of the ProjectDiscovery suite; pairs cleanly with
  [Nuclei](nuclei.md) and other PD tools that read URLs from stdin.
- Headless mode is slower but essential for modern SPA/JS-heavy apps.
- Full flag list and config docs: https://github.com/projectdiscovery/katana
