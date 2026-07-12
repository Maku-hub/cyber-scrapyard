# Recon Methodology

> A repeatable workflow for the reconnaissance and scanning phase: move from
> "what hosts exist" down to "what specific, researchable software is running"
> before you interact with anything in depth.

- **Type:** workflow / reference

## Description

Reconnaissance is where almost every engagement starts. The goal is to enumerate
the attack surface in layers — live hosts, then open ports, then services and
versions, then hidden paths — and only then research each finding for known
weaknesses. Choosing the right tools depends on scale:

- **Few services / a single host** — [Nmap](../recon-scanning/nmap.md) alone is
  enough.
- **Large networks** — run `masscan` first to find open ports fast, then feed
  those ports to `nmap` for detailed fingerprinting.

## The workflow

```bash
# 1. Discover live hosts (ping sweep); import the result into your notes/Metasploit
nmap -sn 10.10.10.0/24

# 2. Find open ports quickly across a large range
masscan -p0-65535 10.10.10.0/24 --rate=2000 -Pn

# 3. Fingerprint services and OS (banners) on the open ports
nmap -sV -O -p <open-ports> 10.10.10.10
# inside Metasploit the equivalent is:  db_nmap -sV -O ...

# 4. Probe services manually to confirm what they are
nc -nv 10.10.10.10 <port>
curl -i http://10.10.10.10:<port>
telnet 10.10.10.10 <port>

# 5. Enumerate interesting paths on web servers
ffuf -w common.txt -u http://10.10.10.10:<port>/FUZZ
feroxbuster -u http://10.10.10.10:<port>
```

6. **Research** — turn observations into leads:
   - Outdated or misconfigured services?
   - Files leaking excessive information?
   - Known CVEs? Search [CVEdetails](https://www.cvedetails.com/), or a targeted
     query like `"<service> intitle:poc site:github.com"`.
   - If a lab task allows it, work a service through to a proof-of-concept RCE.

## A worked mini-exercise (from the source notes)

1. Locate a service on a TCP port in the 5000–7000 range on the lab network.
2. Connect to it and determine what it is; try to pull useful information.
3. Research vulnerabilities for that service/version.
4. Demonstrate impact (e.g. RCE) in the authorized lab only.

## Notes & references

- Rule of thumb: **few targets → Nmap alone; large ranges → Masscan first, then
  Nmap on the ports Masscan found.**
- See the tool pages in [Reconnaissance & Scanning](../recon-scanning/) and the
  end-to-end examples in [Sample Walkthroughs](sample-walkthroughs.md).
- Example security test write-up:
  <https://sekurak.pl/nmap-w-akcji-przykladowy-test-bezpieczenstwa/>
