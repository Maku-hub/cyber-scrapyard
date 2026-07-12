# Shodan

> The search engine for internet-connected devices: query the world's exposed
> servers, cameras, ICS/SCADA, and IoT by service, banner, location, and more.

- **Link:** https://www.shodan.io (Python library: https://github.com/achillean/shodan-python)
- **Type:** freemium (free tier + paid memberships/API credits)
- **Platform:** web app, REST API, and CLI (`pip install shodan`)

## Description

Shodan continuously scans the public internet and indexes the banners it
collects, so instead of scanning a target yourself you can look up what's
already known about it — passively and without sending a single packet. It's
invaluable for mapping an organisation's external attack surface, finding
exposed services, and researching how widespread a given product or
misconfiguration is. The web UI is great for exploration; the CLI and Python
library are what you script against.

## Installation

```bash
# Install the CLI + Python library
pip install shodan

# Store your API key (from your account page) for the CLI
shodan init YOUR_API_KEY
```

## Usage examples

```bash
# Summary of what Shodan knows about a host (no packets sent to it)
shodan host 1.1.1.1

# Search and print matching IPs
shodan search "apache country:GB"

# Count results without spending query credits on full output
shodan count "port:5900 has_screenshot:true"

# Download results to a file, then parse fields out of it
shodan download results "product:nginx port:443"
shodan parse --fields ip_str,port,org results.json.gz

# Live view of your own scan credits / plan
shodan info
```

### Useful search dorks

```text
# Devices that have a screenshot (RDP/VNC/RTSP/etc.)
has_screenshot:true
has_screenshot:true country:gb
has_screenshot:true country:gb port:5900   # VNC screenshots in the UK

# Filter by server banner and country
"Server: nginx" country:gb

# Networked printers (HP LaserJet on the JetDirect port)
port:9100 product:"LaserJet"

# Everything in a specific netblock
net:17.0.0.0/8
net:17.0.0.0/8 port:5060                  # SIP/VoIP in that range
net:17.0.0.0/8 Server: nginx/             # nginx hosts in that range
```

### JARM fingerprinting (spotting C2 servers)

```text
# JARM is a TLS fingerprint; matching a known-bad hash can surface C2 listeners.
# Search Shodan for a specific JARM value (example: a Cobalt Strike default):
ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
```

## Notes & references

- Common filters: `port:`, `country:`, `org:`, `net:`, `product:`, `hostname:`,
  `ssl.cert.subject.cn:`, `has_screenshot:`, `vuln:` (CVE, paid plans).
- JARM background and tooling: https://github.com/salesforce/jarm ; a curated
  list of C2 JARM values: https://github.com/cedowens/C2-JARM ; browse JARM
  facets in Shodan, e.g.
  `https://www.shodan.io/search/facet?query=nginx&facet=ssl.jarm`.
- [Smap](../recon-scanning/smap.md) reuses Shodan data behind an Nmap-style CLI.
- ZoomEye (https://www.zoomeye.ai) is a comparable alternative dataset; see also
  [Censys](censys.md).
- Only shows publicly reachable hosts previously observed by Shodan — data may
  be stale, so confirm findings with active recon when it matters.
