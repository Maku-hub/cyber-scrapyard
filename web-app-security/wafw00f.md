# wafw00f

> Fingerprints the Web Application Firewall (WAF) sitting in front of a site, so
> you know what's filtering your payloads before you waste time on them.

- **Link:** https://github.com/EnableSecurity/wafw00f
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

wafw00f sends a series of normal and deliberately malicious requests to a target
and analyses the responses — status codes, headers, cookies, and block pages —
to identify which WAF (if any) is protecting the application. Knowing the WAF up
front tells you why your requests get dropped and which evasion or encoding
tricks are worth trying. It's one of the first things to run when an app appears
to silently reject payloads.

## Installation

```bash
# Install from PyPI (isolated, recommended)
pipx install wafw00f
```

## Usage examples

```bash
# Detect the WAF in front of a single target
wafw00f https://target.example.com

# List every WAF wafw00f can currently fingerprint
wafw00f -l

# Test multiple targets from a file
wafw00f -i targets.txt

# Find ALL matching WAFs, not just the first (some stacks chain several)
wafw00f -a https://target.example.com

# Increase verbosity to see the requests and detection logic
wafw00f -v https://target.example.com

# Save results as JSON for later processing
wafw00f https://target.example.com -o results.json -f json
```

## Notes & references

- A "no WAF detected" result is not a guarantee — generic/custom WAFs may not
  match any signature.
- Once you know the WAF, tune payload encoding accordingly (e.g. with
  [dalfox](dalfox.md) or [sqlmap](sqlmap.md) tamper scripts).
- Maintained by EnableSecurity; docs and signature list live in the repo README:
  https://github.com/EnableSecurity/wafw00f
