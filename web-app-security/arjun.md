# Arjun

> Finds hidden HTTP parameters an app accepts but never documents — the inputs
> that so often hide IDOR, injection, and access-control bugs.

- **Link:** https://github.com/s0md3v/Arjun
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

Arjun is an HTTP parameter discovery suite. Given a URL, it brute-forces a
wordlist of likely parameter names and detects which ones the server actually
reacts to by watching for changes in response length, status, and content. Those
undocumented parameters are prime testing ground — they're exactly the inputs
that bypass validation. Arjun uses smart request-bundling so it stays fast even
against large wordlists.

## Installation

```bash
# Install from PyPI (isolated, recommended)
pipx install arjun
```

## Usage examples

```bash
# Discover GET parameters on a target
arjun -u https://target.example.com/endpoint

# Test for POST parameters instead
arjun -u https://target.example.com/endpoint -m POST

# Test JSON-body parameters
arjun -u https://target.example.com/api -m JSON

# Use a custom parameter wordlist
arjun -u https://target.example.com/endpoint -w params.txt

# Pass custom headers (e.g. an auth token)
arjun -u https://target.example.com/api --headers "Authorization: Bearer TOKEN"

# Scan many URLs from a file and save results as JSON
arjun -i urls.txt -oJ arjun.json
```

## Notes & references

- Feed discovered parameters into scanners like [dalfox](dalfox.md),
  [sqlmap](sqlmap.md), or [ffuf](ffuf.md) for deeper testing.
- Pairs well with a crawler such as [katana](katana.md) to first collect
  endpoints worth mining.
- By the author of many s0md3v tools; docs: https://github.com/s0md3v/Arjun
