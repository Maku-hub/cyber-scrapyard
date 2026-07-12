# Reference Sites & Cheat Sheets

Handy online lookup tools, search engines, and cheat sheets that come up
constantly during recon, analysis, and exploitation. Bookmark the ones you find
yourself reaching for — most cost nothing and answer a question faster than any
scan.

## Certificate & DNS intelligence

- **crt.sh** — https://crt.sh
  Certificate Transparency log search. Query `%.example.com` to enumerate
  subdomains from issued TLS certificates. E.g. `%.bbc.co.uk`, `%.tesco.com`.
- **SecurityTrails** — https://securitytrails.com
  Domain, DNS record, and **historical DNS** data — useful for finding a site's
  real origin IP behind a Cloudflare/WAF.
- **DomainTools Whois** — https://whois.domaintools.com
  WHOIS records with history and related-domain pivots.
- **Phonebook.cz** — https://phonebook.cz
  Lists all domains, email addresses, and URLs for a given domain.
- **IPLocation.net** — https://www.iplocation.net
  Quick geolocation and network info for an IP address.

## Internet-wide device & tech search

- **Shodan** — https://www.shodan.io
  The "search engine for the Internet of Things" — find exposed hosts,
  services, and devices. Example queries: `port:9100 product:"LaserJet"`,
  `has_screenshot:yes country:gb`, `net:17.0.0.0/8`.
- **ZoomEye** — https://www.zoomeye.hk
  Alternative internet-exposure search engine (the "Chinese Shodan").
- **BuiltWith** — https://builtwith.com
  Profiles the technology stack (CMS, frameworks, analytics) a website runs.
- **PublicWWW** — https://publicwww.com
  Search the *source code* of web pages for snippets, keys, and trackers.
- **WiGLE** — https://wigle.net
  Crowd-sourced database of Wi-Fi networks mapped by location.

## TLS & service fingerprinting

- **Qualys SSL Labs** — https://www.ssllabs.com/ssltest/
  Grades a site's TLS configuration and flags weak ciphers/protocols.
- **Mozilla SSL Config Generator** — https://ssl-config.mozilla.org
  Generates hardened TLS config for common web servers.
- **JARM** — https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/
  Active TLS-server fingerprinting: 10 crafted Client Hellos produce a signature
  that can identify a service (and hunt C2 servers, e.g. Cobalt Strike, on
  Shodan). Tool: https://github.com/salesforce/jarm ; known C2 values:
  https://github.com/cedowens/C2-JARM
- **JA3 / JA3S** — https://www.bussink.net/ja3-and-ja3s-or-the-new-jarm/
  TLS *client* (JA3) and *server* (JA3S) fingerprinting from the handshake.

## Google dorking

- **Google Hacking Database (GHDB)** — https://www.exploit-db.com/google-hacking-database/
  Catalog of search-operator queries that surface exposed files, panels, and
  errors. Examples:
  ```text
  site:gov.pl "Index of" "backup"
  "Index of" "backup" filetype:sql
  filetype:sql inurl:wp-content/backup-db
  intitle:"index of" "mysql warning:"
  ```

## Offensive cheat sheets & payloads

- **HackTricks** — https://book.hacktricks.wiki
  Enormous, constantly updated wiki of pentest techniques for nearly every
  service, platform, and privilege-escalation path.
- **GTFOBins** — https://gtfobins.github.io
  How to abuse legit Unix binaries to break out of restricted shells and
  escalate privileges.
- **LOLBAS** — https://lolbas-project.github.io
  The Windows equivalent — "living off the land" binaries, scripts, and
  libraries attackers (ab)use.
- **PayloadsAllTheThings** — https://github.com/swisskyrepo/PayloadsAllTheThings
  A huge collection of payloads and bypasses for web and infrastructure attacks.
- **revshells.com** — https://www.revshells.com
  Generates reverse-shell one-liners in every language/shell, with listener
  commands — no more memorizing syntax.
- **HijackLibs** — https://hijacklibs.net
  Reference of DLL-hijacking opportunities in Windows software.
- **KeyHacks** — https://github.com/streaak/keyhacks
  How to validate and abuse leaked API keys and tokens you find.
- **API Security Checklist** — https://github.com/shieldfy/API-Security-Checklist
  Concise checklist for building and testing secure APIs.
- **Penetration Test framework / workbook** —
  http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html and
  https://workbook.securityboat.net
  Methodology references to structure an assessment end to end.

## Data transforms & utilities

- **CyberChef** — https://gchq.github.io/CyberChef/
  The "cyber Swiss-army knife" — encode/decode, encrypt, and analyze data
  through chained operations, all in the browser. Full page:
  [dev-tools/cyberchef.md](../dev-tools/cyberchef.md).
- **CVSS Calculator (FIRST)** — https://www.first.org/cvss/calculator/3.1
  Score a vulnerability's severity using the official CVSS calculator.
- **command-not-found.com** — https://command-not-found.com
  Look up which package provides a given command across distros.
- **Canarytokens** — https://canarytokens.org
  Generate free "tripwire" tokens (URLs, docs, DNS) that alert you when opened —
  handy for detecting intrusions and testing exfil paths.

## See also

- [OSINT](../osint/) — the tooling behind passive reconnaissance.
- [News & Feeds](news-and-feeds.md) — frameworks, advisories, and news sources.
