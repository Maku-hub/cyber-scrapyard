# Web Application Security

Tools for testing the web layer: intercepting and manipulating HTTP(S) traffic,
fingerprinting the tech stack, discovering hidden content, and finding and
exploiting vulnerabilities like SQL injection, XSS, and misconfigurations. This
is where you dig into an application once recon has told you it exists.

## Tools

| Tool | Summary |
| --- | --- |
| [Burp Suite](burp-suite.md) | The de facto intercepting proxy + toolkit — Proxy, Repeater, Intruder, Scanner (Community vs Pro) |
| [OWASP ZAP](owasp-zap.md) | Open-source intercepting proxy and scanner; scriptable and CI-friendly (DAST) |
| [sqlmap](sqlmap.md) | Automated SQL injection detection and exploitation across many DBMSes |
| [Commix](commix.md) | Automated detection and exploitation of OS command-injection flaws |
| [Dalfox](dalfox.md) | Fast Go-based XSS scanner with parameter analysis and DOM verification |
| [ffuf](ffuf.md) | Blazing-fast web fuzzer for content, vhost, and parameter discovery |
| [Katana](katana.md) | Modern crawler mapping endpoints (incl. JS) to feed ffuf/nuclei |
| [Arjun](arjun.md) | HTTP parameter discovery — finds hidden/undocumented inputs |
| [Gobuster](gobuster.md) | Directory/file, DNS subdomain, and virtual-host brute-forcer |
| [feroxbuster](feroxbuster.md) | Fast, automatically recursive content-discovery tool in Rust |
| [Nuclei](nuclei.md) | Template-based scanner for known CVEs, misconfigurations, and exposures |
| [Nikto](nikto.md) | Classic web server scanner for dangerous files and outdated software |
| [WPScan](wpscan.md) | WordPress scanner — enumerate users/plugins/themes and match known vulns |
| [WhatWeb](whatweb.md) | Web technology fingerprinter (server, CMS, frameworks, JS libraries) |
| [wafw00f](wafw00f.md) | WAF fingerprinter — identifies the firewall filtering your requests |
| [testssl.sh](testssl.md) | TLS/SSL configuration and vulnerability tester (protocols, ciphers, certs) |
| [wfuzz & dirsearch](wfuzz-and-fuzzers.md) | Classic content/parameter fuzzers — alternatives to ffuf/gobuster |
| [API & GraphQL testing](api-and-graphql.md) | jwt_tool, graphw00f, InQL & kiterunner — attack JWTs, GraphQL, and REST APIs |

## Typical web testing workflow

1. **Fingerprint the stack** — `whatweb <target>`, `curl -i <target>`; if it's
   WordPress, run [WPScan](wpscan.md).
2. **Discover content** — brute-force paths with [ffuf](ffuf.md),
   [gobuster](gobuster.md), or [feroxbuster](feroxbuster.md).
3. **Map & intercept** — proxy traffic through [Burp Suite](burp-suite.md) or
   [OWASP ZAP](owasp-zap.md); explore the app manually.
4. **Scan for known issues** — [Nuclei](nuclei.md), [Nikto](nikto.md), or the
   ZAP/Burp active scanner.
5. **Exploit findings** — e.g. confirm and dump via [sqlmap](sqlmap.md), or
   tamper requests in Repeater/Intruder.

> Learn the underlying vulnerability classes first: the **OWASP Top 10**
> (https://owasp.org/www-project-top-ten/) and PortSwigger's free **Web Security
> Academy** (https://portswigger.net/web-security) are the standard references.
> See [../learning-resources/](../learning-resources/).

See also: [../recon-scanning/](../recon-scanning/) for host/port/subdomain
discovery that feeds into web testing, and [../osint/](../osint/) for passive
attack-surface mapping.
