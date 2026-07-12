# OSINT (Open-Source Intelligence)

Passive intelligence gathering from public sources — search engines, internet
scan datasets, certificate logs, WHOIS/DNS, and social media. The goal is to map
a target's attack surface and gather context *before* touching it, so much of
this work leaves no trace on the target itself.

## Tools & services

| Tool | Summary |
| --- | --- |
| [Shodan](shodan.md) | Search engine for internet-connected devices — query exposed services by banner, port, product, and location |
| [Censys](censys.md) | Internet-wide host & certificate search with a structured query language; complements Shodan |
| [Certificate Transparency](certificate-transparency.md) | Discover subdomains via public TLS certificate logs (crt.sh, Censys certs) |
| [Maltego](maltego.md) | Visual link-analysis platform for correlating people, domains, and infrastructure |
| [SpiderFoot](spiderfoot.md) | Automated OSINT engine querying 200+ sources and correlating the results |
| [theHarvester](theharvester.md) | Fast email, subdomain, and host gatherer from public sources |
| [Recon-ng](recon-ng.md) | Modular, database-backed recon framework with a Metasploit-style console |
| [People & username OSINT](people-username-osint.md) | Sherlock, Maigret, holehe, WhatsMyName — find accounts by username/email |
| [Have I Been Pwned](haveibeenpwned.md) | Check whether an email, phone, or password appears in a known data breach |
| [GHunt](ghunt.md) | Extract public OSINT from a Google account starting from an email address |
| [ExifTool](exiftool.md) | Read, write, and strip EXIF/IPTC/XMP metadata from images and documents |
| [OSINT Framework](osint-framework.md) | Curated, browsable directory of OSINT resources organised by data type |
| [Google Dorking](google-dorking.md) | Advanced search operators and the Google Hacking Database for passive recon |
| [PhoneInfoga](phoneinfoga.md) | Phone-number OSINT — carrier/line-type lookup and search-engine footprinting |

## Typical OSINT workflow

1. **Scope the organisation** — root domains, netblocks/ASNs, subsidiaries
   (`amass intel`, WHOIS, [recon-ng](recon-ng.md)).
2. **Enumerate infrastructure** — subdomains and hosts via
   [Certificate Transparency](certificate-transparency.md),
   [theHarvester](theharvester.md), and
   [subdomain tooling](../recon-scanning/subdomain-enumeration.md).
3. **Query scan datasets** — check exposure passively with [Shodan](shodan.md)
   and [Censys](censys.md) before sending any packets.
4. **Profile people** — emails and usernames of employees for social-engineering
   assessments ([people & username OSINT](people-username-osint.md)).
5. **Correlate & visualise** — tie it together in
   [Maltego](maltego.md) or [SpiderFoot](spiderfoot.md).

> Rule of thumb: **exhaust passive sources first.** Every host you find in
> public data is one you didn't have to scan to discover.

Handy free sources: crt.sh (certificates), RIPE full-text WHOIS
(https://apps.db.ripe.net), the Google Hacking Database
(https://www.exploit-db.com/google-hacking-database), SecurityTrails (DNS
history), and ZoomEye (https://www.zoomeye.ai).

See also: [Reconnaissance & Scanning](../recon-scanning/) for turning discovered
hosts into active scans, and [Web Application Security](../web-app-security/) for
web-layer enumeration.
