# testssl.sh

> A single portable shell script that audits a TLS/SSL endpoint — protocols,
> ciphers, certificate, and known bugs (Heartbleed, ROBOT, POODLE, and more).

- **Link:** https://github.com/drwetter/testssl.sh
- **Type:** open source
- **Platform:** cross-platform (Bash; also shipped as a Docker image)

## Description

testssl.sh checks a server's TLS/SSL configuration end to end: which protocol
versions it offers (SSLv2/3, TLS 1.0-1.3), the cipher suites and their strength,
certificate details and chain, forward secrecy, HSTS, and a long list of named
vulnerabilities. It's a single dependency-free script, so it runs anywhere
without installation, and its output is graded (good/warn/critical) which makes
it easy to hand to a report. Ideal for verifying hardening after a change.

## Installation

```bash
# Clone the repo — no build step, the script is self-contained
git clone --depth 1 https://github.com/drwetter/testssl.sh.git && cd testssl.sh

# Or run it via the official Docker image
docker run --rm -ti drwetter/testssl.sh https://target.example.com
```

## Usage examples

```bash
# Full default assessment of an HTTPS server
./testssl.sh https://target.example.com

# Test a specific host and non-standard port
./testssl.sh target.example.com:8443

# Check only which protocols are supported
./testssl.sh -p target.example.com

# Check only the cipher suites on offer
./testssl.sh -E target.example.com

# Scan only for known named vulnerabilities (Heartbleed, ROBOT, etc.)
./testssl.sh -U target.example.com

# Test a mail server's STARTTLS (smtp/imap/pop3/etc.)
./testssl.sh -t smtp mail.example.com:25

# Save graded output as HTML and JSON for reporting
./testssl.sh --htmlfile report.html --jsonfile report.json target.example.com
```

## Notes & references

- No compilation needed — it only requires a reasonably modern Bash and OpenSSL;
  it bundles its own OpenSSL builds for the trickier checks.
- Complementary online checker for public sites: SSL Labs
  (https://www.ssllabs.com/ssltest/).
- Full flag reference and docs: https://github.com/drwetter/testssl.sh
- Covers the transport-security phase of the
  [Web Application Assessment](../scenarios/web-app-assessment.md) scenario.
