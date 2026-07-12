# Certificate Transparency

> Public logs of every TLS certificate ever issued — a passive goldmine for
> discovering subdomains and hidden infrastructure without touching the target.

- **Link:** https://crt.sh (also Censys certs: https://search.censys.io)
- **Type:** free (public logs / web services)
- **Platform:** web + API (query from a browser or `curl`)

## Description

Certificate Transparency (CT) is a system where Certificate Authorities publish
every certificate they issue to public, append-only logs. For reconnaissance
that's extremely useful: when an organisation gets a cert for
`internal-dev.example.com`, that hostname becomes searchable — even if it's not
in DNS or linked anywhere. Because you're querying public logs, not the target,
CT discovery is completely passive and often reveals staging, admin, and
forgotten hosts that other methods miss. **crt.sh** is the go-to free front-end;
Censys and others index the same logs with richer filtering.

## Installation

No install required — query the web services directly.

```bash
# crt.sh has a JSON endpoint, so curl + jq works well
sudo apt install jq
```

## Usage examples

### crt.sh queries

Enter these in the crt.sh search box (`%` is the SQL wildcard):

```text
# All certificates issued for subdomains of a domain
%.example.com

# Real-world examples
%.corp.google.com
%.tesco.com
%.tesco.pl
%.bbc.co.uk
%.gov.pl
```

### Scripting crt.sh with curl

```bash
# Pull unique subdomains for a domain as JSON, then extract & dedupe names
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

### Censys certificate search

```text
# In the Censys UI (Certificates index): certs naming a domain's subdomains
names: example.com
```

## Notes & references

- CT results include wildcard (`*.example.com`) and expired certs — resolve the
  names afterwards (e.g. with [dnsx](../recon-scanning/subdomain-enumeration.md))
  to keep only live hosts.
- Completely passive: nothing is sent to the target, so it's safe for the
  earliest, quietest phase of recon.
- Feeds directly into [subdomain enumeration](../recon-scanning/subdomain-enumeration.md);
  tools like `subfinder` and [Amass](../recon-scanning/amass.md) already query CT
  among many sources.
- Other CT front-ends/indexes: [Censys](censys.md), Google's CT search, and
  SecurityTrails (https://securitytrails.com) for DNS history.
