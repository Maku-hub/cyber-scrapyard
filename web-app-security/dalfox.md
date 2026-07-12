# Dalfox

> Fast, Go-based XSS scanner that does parameter analysis, payload generation,
> and DOM verification — built to slot into automation pipelines.

- **Link:** https://github.com/hahwul/dalfox
- **Type:** open source
- **Platform:** cross-platform (Go)

## Description

Dalfox (from "Finder Of XSS") is a powerful open-source tool focused on automated
XSS scanning and parameter analysis. It reflects payloads, checks how they're
encoded/reflected, generates context-aware payloads, and can verify execution
via a headless browser to cut down false positives. Because it reads targets
from stdin, it pairs naturally with crawlers like [katana](katana.md) and
parameter miners like [Arjun](arjun.md) for end-to-end XSS hunting.

## Installation

```bash
# Install the latest release with the Go toolchain
go install github.com/hahwul/dalfox/v2@latest
```

## Usage examples

```bash
# Scan a single URL with query parameters
dalfox url "https://target.example.com/search?q=test"

# Pipe a list of URLs (e.g. from katana/gau) into pipe mode
cat urls.txt | dalfox pipe

# Scan a file of URLs
dalfox file urls.txt

# Add custom headers (e.g. an authenticated session cookie)
dalfox url "https://target.example.com/?q=1" -H "Cookie: session=abc123"

# Use a blind XSS callback to catch out-of-band execution
dalfox url "https://target.example.com/?q=1" -b https://your.xss.ht

# Mining-only: discover reflected parameters without full scanning
dalfox url "https://target.example.com/" --only-discovery

# Output findings as JSON for reporting/automation
dalfox url "https://target.example.com/?q=1" --format json -o dalfox.json
```

## Notes & references

- Blind XSS (`-b`) needs a collector such as XSS Hunter or your own callback
  server to receive out-of-band hits.
- Feed it discovered endpoints from [katana](katana.md) and parameters from
  [Arjun](arjun.md) to widen coverage.
- Docs and payload details: https://github.com/hahwul/dalfox and
  https://dalfox.hahwul.com
