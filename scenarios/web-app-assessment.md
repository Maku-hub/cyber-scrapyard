# Web Application Assessment

> A web application / URL is in scope. Map it, fingerprint the stack, discover
> hidden content, then find and **validate** web vulnerabilities.

## Scope & assumptions

- **Authorized use only.** Work strictly within the target list and rules of
  engagement — including which subdomains, environments (prod vs. staging), and
  test-account credentials you may use. Automated scanners can be destructive;
  agree on rate limits and blackout windows first.
- You start with at least one in-scope hostname or URL (ideally the asset
  inventory from [External Recon & OSINT](external-recon-osint.md)).
- Goal: identify vulnerabilities and confirm them with a minimal, safe
  proof-of-concept — not to cause damage.

## Phase 1 — Expand the surface: subdomains & live hosts

Start by widening the target within scope and finding which hosts actually
respond, so you don't waste time on dead names.

- Enumerate names via [subdomain enumeration](../recon-scanning/subdomain-enumeration.md).
- Probe them for live HTTP/S services, titles, status codes, and tech hints with
  [httpx](../recon-scanning/httpx.md).

```bash
# Which of the discovered hosts actually serve web content?
cat subdomains.txt | httpx -title -status-code -tech-detect
```

## Phase 2 — Fingerprint the stack & detect a WAF

Knowing the server, framework, CMS, and whether a WAF sits in front shapes every
later choice (payload encoding, rate, tooling).

- Fingerprint technologies with [WhatWeb](../web-app-security/whatweb.md).
- Detect and identify any web application firewall with [wafw00f](../web-app-security/wafw00f.md)
  so you can plan evasion or, better, coordinate an allowlist with the client.

```bash
whatweb -a 3 https://app.example.com     # aggressive fingerprint
wafw00f https://app.example.com          # is there a WAF, and whose?
```

## Phase 3 — Crawl & content discovery

Build a map of endpoints, parameters, and hidden paths. Crawling finds linked
content; brute-force discovery finds the unlinked (admin panels, backups, old
APIs).

- Crawl the app (including JS-derived endpoints) with [Katana](../web-app-security/katana.md).
- Brute-force directories/files with [Gobuster](../web-app-security/gobuster.md)
  and fuzz paths/parameters/vhosts flexibly with [ffuf](../web-app-security/ffuf.md).

```bash
katana -u https://app.example.com -jc            # crawl + parse JS for endpoints
ffuf -w wordlist.txt -u https://app.example.com/FUZZ -mc 200,301,403
```

## Phase 4 — Proxy & manual testing

Automation misses logic flaws. Route traffic through an intercepting proxy to
understand auth, session handling, and business logic, and to hand-craft
requests.

- Drive manual testing through [Burp Suite](../web-app-security/burp-suite.md)
  or the open-source [OWASP ZAP](../web-app-security/owasp-zap.md) — intercept,
  repeat, and tamper with requests to probe access control and workflow logic.

## Phase 5 — Automated vulnerability scan

With the app mapped, run templated checks for known CVEs, misconfigurations, and
exposures to catch the low-hanging fruit quickly.

- Scan with [Nuclei](../web-app-security/nuclei.md) using relevant template tags.
- If it's WordPress, pivot to the specialised [WPScan](../web-app-security/wpscan.md)
  for plugin/theme/user enumeration.

```bash
nuclei -u https://app.example.com -tags cve,exposure,misconfig
wpscan --url https://blog.example.com --enumerate vp,u   # WordPress only
```

## Phase 6 — Targeted exploitation & validation

Turn findings into confirmed vulnerabilities with focused, minimally invasive
proofs-of-concept. Discover hidden parameters first, then test each injection
class with the right specialist tool.

- Find undocumented parameters with [Arjun](../web-app-security/arjun.md).
- Validate SQL injection with [sqlmap](../web-app-security/sqlmap.md), XSS with
  [Dalfox](../web-app-security/dalfox.md), and OS command injection with
  [Commix](../web-app-security/commix.md) — always with the least-impact options
  and against test data only.

```bash
arjun -u https://app.example.com/search            # discover hidden params
sqlmap -u 'https://app.example.com/item?id=1' --batch --level 2 --risk 1
dalfox url 'https://app.example.com/search?q=test'
```

## Phase 7 — Transport security (TLS)

Round out the assessment with the crypto layer: protocol versions, cipher
suites, certificate validity, and known TLS flaws.

- Audit TLS configuration with [testssl.sh](../web-app-security/testssl.md).

```bash
testssl.sh https://app.example.com
```

## Reporting / next steps

For each finding, record the request/response, reproduction steps, impact, and a
remediation recommendation, and map it to the relevant
[OWASP](../methodology/owasp.md) category. Rank by real risk (exploitability ×
impact), not just scanner severity. Re-test after fixes. Keep raw scanner output
as an appendix but lead with validated issues — see the
[Web Application Security](../web-app-security/) category for deeper tool usage.
