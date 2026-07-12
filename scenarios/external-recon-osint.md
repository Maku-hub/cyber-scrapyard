# External Recon & OSINT

> You have only an organisation's name and primary domain. Map its external
> footprint **passively** — no packets to the target's production systems —
> before any active testing begins.

## Scope & assumptions

- **Authorized use only.** Passive OSINT still needs a written scope: agree which
  domains, brands, and subsidiaries are in bounds, and confirm the client is
  comfortable with third-party data sources (breach dumps, certificate logs).
- You start with an organisation name and one apex domain (e.g. `example.com`).
- The goal of this phase is *breadth*: discover assets, exposure, and people —
  not to exploit anything. Everything here queries public data or third-party
  archives, so it should leave no trace on the target.

## Phase 1 — Define the real scope (domains, brands, ASNs)

Before enumerating, work out what actually belongs to the org: sibling domains,
acquired brands, and the IP ranges (ASNs) it owns. This keeps later phases
focused and in-scope.

- Use [theHarvester](../osint/theharvester.md) for a fast first pass at domains,
  hosts, and emails tied to the name.
- Feed the discovered netblocks into [Censys](../osint/censys.md) and
  [Shodan](../osint/shodan.md) to confirm which IP space and ASNs the org
  operates.

```bash
# First-pass footprint from multiple public sources
theHarvester -d example.com -b bing,crtsh,duckduckgo
```

## Phase 2 — Certificate transparency & subdomain enumeration

Public CA logs reveal hostnames the org may never have advertised — staging,
VPN, dev, and internal-sounding names all leak here. Combine CT data with
passive DNS aggregation for the widest asset list.

- Mine CT logs via [Certificate Transparency](../osint/certificate-transparency.md).
- Run [Amass](../recon-scanning/amass.md) in passive mode and consult the broader
  [subdomain enumeration](../recon-scanning/subdomain-enumeration.md) page for
  additional passive sources and how to de-duplicate results.

```bash
# Certificate transparency via crt.sh, extract unique hostnames
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u
# Passive-only Amass (no direct resolution against the target)
amass enum -passive -d example.com
```

## Phase 3 — Public exposure of assets

For each host and IP now in scope, check what the internet already sees:
open services, banners, exposed panels, cloud buckets, and indexed files.

- Query [Shodan](../osint/shodan.md) and [Censys](../osint/censys.md) by
  hostname, IP, and certificate to inventory exposed services without scanning.
- Use [Google dorking](../osint/google-dorking.md) to surface exposed documents,
  login portals, and misindexed directories.
- Pull metadata (authors, software, internal paths, usernames) from any public
  documents you find with [ExifTool](../osint/exiftool.md).

```bash
# Everything Shodan already knows about the org's IP space (no scan sent)
shodan search 'org:"Example Corp"'
# Metadata that often leaks usernames and internal server names
exiftool report-q3.pdf
```

## Phase 4 — People, emails & breach data

People are a big part of the external attack surface. Enumerate likely email
formats and staff, then check whether their credentials already appear in known
breaches — useful for password-spray risk assessment and phishing-awareness
findings.

- Correlate hosts, emails, and infrastructure at scale with
  [SpiderFoot](../osint/spiderfoot.md), and visualise the relationships in
  [Maltego](../osint/maltego.md).
- Check harvested emails/domains against [Have I Been Pwned](../osint/haveibeenpwned.md)
  to flag exposed accounts (query the API within its terms — do not attempt to
  use leaked passwords).

```bash
# Automated multi-source correlation, headless
spiderfoot -s example.com -m sfp_dnsresolve,sfp_crt,sfp_hunter
```

## Reporting / next steps

Consolidate everything into a single asset inventory: apex + sibling domains,
subdomains, live IPs/ASNs, exposed services, leaked documents, and
breach-exposed accounts. Flag anything unexpected (shadow IT, forgotten staging,
expired certs) for the client. This inventory becomes the authorized target list
for active phases — see the [Web Application Assessment](web-app-assessment.md)
and [Internal Network & AD](internal-network-ad.md) scenarios, and the
[Reconnaissance & Scanning](../recon-scanning/) category for the transition from
passive to active. Confirm scope before sending a single active packet.
