# Linux Server Assessment

> You have a single Linux server (say, a "Debian 13" box) in scope. Assess its
> exposure, patch level, configuration hardening, and — if you gain access —
> local privilege-escalation paths.

## Scope & assumptions

- **Authorized use only.** Work within a written scope that names the host/IP,
  the testing window, and whether you have credentials or must start black-box.
  Confirm whether exploitation and privesc are permitted or the engagement is
  audit-only.
- One reachable Linux host. You may begin unauthenticated (external view) and
  later receive SSH credentials for the authenticated hardening audit.
- The flow moves from *outside-in* (what the network sees) to *inside-out* (what
  a logged-in user or attacker could do), so early phases are non-invasive and
  the intrusive checks come last.

## Phase 1 — Port & service discovery

Establish exactly what the host exposes before drawing any conclusions. Fast
port discovery narrows the field; version detection tells you what's actually
listening.

- Sweep ports quickly with [Naabu](../recon-scanning/naabu.md), then feed the
  open ports into [Nmap](../recon-scanning/nmap.md) for service/version and OS
  fingerprinting.

```bash
naabu -host 10.0.0.5 -o ports.txt          # fast TCP port sweep
nmap -sV -O -p$(paste -sd, ports.txt) 10.0.0.5   # version + OS on open ports only
```

## Phase 2 — Network vulnerability scan

With services enumerated, look for known CVEs and misconfigurations from the
network side. This flags unpatched daemons and weak configs worth validating.

- Run an authenticated or unauthenticated scan with
  [OpenVAS / Greenbone](../vulnerability-scanners/openvas-greenbone.md) or
  [Nessus](../vulnerability-scanners/nessus.md) against the host.
- Cross-reference any interesting version banners against public exploits with
  [SearchSploit](../exploitation-c2/searchsploit.md) to gauge exploitability.

```bash
searchsploit "openssh 8.2"    # is there a public exploit for this version?
```

## Phase 3 — Web application checks (if a web service is present)

If Phase 1 found HTTP(S), quickly triage the web surface for exposed panels,
default files, and templated vulnerabilities before deeper manual work.

- Point [Nuclei](../web-app-security/nuclei.md) at the web endpoints to run its
  community templates (CVEs, exposures, misconfigurations).

```bash
nuclei -u https://10.0.0.5 -tags cve,exposure,misconfig
```

## Phase 4 — Authenticated configuration & hardening audit

Once you have credentials, audit the box from the inside against hardening
baselines — this catches weak sysctl/SSH/permission settings that a network scan
never sees.

- Run [Lynis](../vulnerability-scanners/lynis.md) for a broad system hardening
  audit, and [OpenSCAP](../vulnerability-scanners/openscap.md) to measure the
  host against a formal profile (e.g. CIS or DISA STIG).
- Use the [Linux OS security](../os-security/linux.md) page as the reference for
  what "good" looks like (services, users, kernel, file permissions).

```bash
lynis audit system                          # broad hardening audit with a score
oscap xccdf eval --profile cis ssg-debian-ds.xml   # measure against a CIS profile
```

## Phase 5 — Local privilege escalation (if access is obtained and in scope)

If you land a shell as an unprivileged user and privesc is authorized, enumerate
local escalation paths methodically rather than guessing.

- Run [LinPEAS](../post-exploitation/linpeas-winpeas.md) for automated local
  enumeration (SUID binaries, cron, writable paths, creds), and consult the
  [privilege escalation](../post-exploitation/privilege-escalation.md) page to
  interpret and exploit the findings.
- If you need to catch a shell during an exploit, see
  [reverse shells](../post-exploitation/reverse-shells.md) for reliable one-liners
  and stabilisation.

```bash
./linpeas.sh -a | tee linpeas.out          # automated local privesc enumeration
```

## Reporting / next steps

Consolidate findings into a single report: exposed services and their patch
state, confirmed CVEs (with exploitability notes), hardening gaps from Lynis/
OpenSCAP mapped to a baseline, and any privilege-escalation chain you proved.
Prioritise by real risk (reachable + exploitable) and give concrete remediation
— patch versions, config changes, and the relevant hardening controls from the
[Linux OS security](../os-security/linux.md) page. Re-scan after fixes to confirm
closure.
