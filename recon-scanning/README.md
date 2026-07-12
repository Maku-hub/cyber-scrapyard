# Reconnaissance & Scanning

Tools for discovering live hosts, open ports, running services, and attack
surface. This is where almost every engagement starts: map what's there before
deciding how to interact with it.

## Tools

| Tool | Summary |
| --- | --- |
| [Nmap](nmap.md) | The de facto port scanner: host discovery, service/OS fingerprinting, and a scripting engine (NSE) |
| [Masscan](masscan.md) | Internet-scale asynchronous port scanner — extremely fast, pair it with Nmap |
| [RustScan](rustscan.md) | Fast modern port scanner that auto-pipes open ports into Nmap |
| [Smap](smap.md) | Nmap-compatible scanner that pulls results from Shodan (no packets sent to target) |
| [naabu](naabu.md) | Fast Go port scanner (SYN/CONNECT) that pipes cleanly into httpx and Nmap |
| [httpx](httpx.md) | Fast HTTP prober/toolkit — confirms live web servers and grabs titles, status codes and tech |
| [Amass](amass.md) | Subdomain enumeration and external attack-surface mapping |
| [Subdomain & DNS discovery](subdomain-enumeration.md) | subfinder, assetfinder, gobuster dns, dnsx |
| [DNSRecon](dnsrecon.md) | DNS enumeration: records, zone transfers, brute-force and reverse lookups |
| [fierce](fierce.md) | DNS recon / subdomain discovery that also locates adjacent IP space |
| [AutoRecon](autorecon.md) | Orchestrates multiple recon tools in parallel with tidy per-target output |
| [Web archive URLs](web-archive-urls.md) | gau & waybackurls — mine known URLs from Wayback/Common Crawl before crawling or fuzzing |
| [Web screenshotting](screenshotting.md) | gowitness & EyeWitness — bulk visual triage of live web hosts |

## Typical recon workflow

1. **Discover live hosts** — `nmap -sn 10.0.0.0/24` (import into notes/Metasploit).
2. **Find open ports fast** — `masscan -p0-65535 10.0.0.0/24 --rate=2000`.
3. **Fingerprint services & OS** — `nmap -sV -O -p <open ports> <host>`.
4. **Probe manually** — `nc`, `curl`, `telnet`, browser + proxy.
5. **Enumerate web paths / subdomains** — `ffuf`, `feroxbuster`, `amass`.
6. **Research findings** — outdated versions? misconfigurations? known CVEs?

> Rule of thumb: **few targets → Nmap alone. Large ranges → Masscan first, then
> Nmap on the ports Masscan found.**

See also: [Web Application Security](../web-app-security/) for web-layer
fuzzing/enumeration, and [OSINT](../osint/) for passive discovery.
