# Censys

> An internet-wide scan and certificate search engine: query hosts, services,
> and TLS certificates with a rich, structured query language.

- **Link:** https://search.censys.io
- **Type:** freemium (free tier + paid plans; API available)
- **Platform:** web app, REST API, and CLI (`pip install censys`)

## Description

Censys continuously scans the internet and parses what it finds into structured,
searchable fields — protocols, software, TLS certificates, ASNs, and more. It's
a close cousin of [Shodan](shodan.md), and the two datasets often complement
each other: cross-checking both gives a fuller view of a target's exposure. Its
certificate search is especially strong for discovering subdomains and related
infrastructure that share the same TLS certs. A structured query language lets
you filter precisely and pivot from a host to everything that looks like it.

## Installation

```bash
# Install the CLI + Python library
pip install censys

# Configure with your API ID/secret (from your account page)
censys config
```

## Usage examples

```bash
# Search hosts running a given service in a country
censys search "services.service_name: HTTP and location.country: Germany"

# Look up everything known about a single host
censys view 8.8.8.8

# Find certificates for a domain (great for subdomain discovery)
censys search "names: example.com" --index-type certs
```

### Web UI query examples

```text
# Hosts by service and software
services.service_name: SSH and services.software.product: OpenSSH

# Hosts presenting a certificate for a domain (surfaces subdomains)
services.tls.certificates.leaf_data.subject.common_name: *.example.com

# Everything in an organisation / ASN
autonomous_system.organization: "Example Corp"
```

## Notes & references

- Certificate search is the standout feature for mapping infrastructure — pair
  it with [Certificate Transparency](certificate-transparency.md) for subdomain
  discovery.
- Use alongside [Shodan](shodan.md): different scanners see different things, so
  querying both reduces blind spots.
- Field names differ from Shodan's — see the query reference:
  https://search.censys.io/search/definitions
- Passive by nature: results come from Censys's scans, not from you touching the
  target.
