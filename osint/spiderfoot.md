# SpiderFoot

> An automated OSINT engine: point it at a target and it queries 200+ data
> sources to enumerate infrastructure, leaks, and exposure, then correlates it.

- **Link:** https://github.com/smicallef/spiderfoot
- **Type:** open source (SpiderFoot HX is a hosted commercial edition)
- **Platform:** cross-platform (Python; web UI + CLI)

## Description

SpiderFoot automates the tedious fan-out of reconnaissance. Give it a seed —
a domain, IP, email, name, or username — and it fires off queries to a huge
library of modules (WHOIS, DNS, certificate transparency, Shodan, Have I Been
Pwned, VirusTotal, search engines, social media, and many more), then links the
findings together and flags anything interesting. The built-in web UI makes it
easy to launch scans, browse results by type, and visualise relationships. It's
the fastest way to get a broad first look at a target's footprint before diving
in manually.

## Installation

```bash
# Clone and install dependencies
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip install -r requirements.txt

# Start the web UI (then browse to http://127.0.0.1:5001)
python3 sf.py -l 127.0.0.1:5001
```

## Usage examples

```bash
# List all available modules
python3 sf.py -M

# Command-line scan of a domain, output as CSV
python3 sf.py -s example.com -o csv

# Scan but only use passive modules (nothing sent to the target)
python3 sf.py -s example.com -t DOMAIN_NAME -u passive

# Scan a specific target type (email address) with chosen modules
python3 sf.py -s target@example.com -m sfp_haveibeenpwned,sfp_hunter
```

## Notes & references

- Enter API keys under **Settings** in the web UI to unlock the most valuable
  modules (Shodan, Censys, HIBP, VirusTotal, SecurityTrails, etc.).
- Scan **use cases** let you pick intent: *Passive* (stealthy), *Footprint*,
  *Investigate*, or *All* — start passive to avoid touching the target.
- Overlaps with [theHarvester](theharvester.md) and [recon-ng](recon-ng.md) but
  is broader and more automated; use it to cast a wide net, then pivot with the
  focused tools.
- Docs: https://www.spiderfoot.net/documentation/
