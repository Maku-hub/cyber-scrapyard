# WhatWeb

> Web technology fingerprinter: identifies the server, CMS, frameworks,
> JavaScript libraries, and more behind a site — fast, passive-friendly recon.

- **Link:** https://github.com/urbanadventurer/WhatWeb
- **Type:** open source
- **Platform:** cross-platform (Ruby)

## Description

WhatWeb tells you what a website is built with — web server, CMS (WordPress,
Joomla, Drupal…), analytics, JavaScript libraries, frameworks, and version hints.
Knowing the stack is the starting point for targeted testing: an outdated CMS or
a specific library version points you straight at relevant known
vulnerabilities. It has aggression levels ranging from a single passive request
to more intrusive probing.

## Installation

```bash
# Debian/Kali package
sudo apt install whatweb

# Or clone from source
git clone https://github.com/urbanadventurer/WhatWeb.git
```

## Usage examples

```bash
# Identify the technologies behind a site (server, CMS, JS libraries, etc.)
whatweb networkchuck.coffee

# Increase aggression for deeper detection (-a 3 = more requests, more detail)
whatweb -a 3 https://target.example.com

# Scan a list of targets and log results as JSON
whatweb -i targets.txt --log-json results.json

# Verbose output showing every plugin match
whatweb -v https://target.example.com
```

## Notes & references

- Aggression levels: `-a 1` (stealthy, one request — the default) … `-a 3`
  (aggressive) … `-a 4` (heavy). Raise it when you need deeper detection.
- Pairs naturally with `curl -i` to read raw response headers and cookies, and
  with [Nikto](nikto.md) / [WPScan](wpscan.md) once you know the stack.
- Similar browser-side tool: Wappalyzer. For attack-surface mapping see
  [../recon-scanning/](../recon-scanning/).
- Docs: https://github.com/urbanadventurer/WhatWeb#readme
