# OWASP ZAP

> The open-source intercepting proxy and web scanner — a free, fully scriptable
> alternative to Burp Suite that fits well into CI/CD pipelines.

- **Link:** https://github.com/zaproxy/zaproxy (site: https://www.zaproxy.org)
- **Type:** open source
- **Platform:** cross-platform (Java)

## Description

ZAP (Zed Attack Proxy) does what Burp's proxy and scanner do, but is free and
open source under the OWASP umbrella. Point your browser at it to intercept and
tamper with traffic, run an automated active scan for common vulnerabilities, or
spider a site to map its attack surface. Its headless daemon mode and Docker
images make it a popular choice for automated security testing in build
pipelines (DAST).

## Installation

```bash
# Debian/Kali package
sudo apt install zaproxy

# Or run the official Docker image (great for CI)
docker pull ghcr.io/zaproxy/zaproxy:stable
```

## Usage examples

```bash
# Launch the GUI (manual testing, proxy on 127.0.0.1:8080 by default)
zaproxy

# Headless baseline scan — passive checks + spider, fails build on findings
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://target.example.com

# Full active scan (intrusive) writing an HTML report
docker run -v $(pwd):/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t https://target.example.com -r report.html

# Run as a daemon and drive it through the REST API / zap-cli
zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.key=changeme
```

## Notes & references

- **Automation Framework** and API let you script crawl → scan → report; ideal
  for DAST in GitLab/GitHub Actions.
- Use the **HUD** (Heads-Up Display) to overlay ZAP controls directly in the
  browser during manual testing.
- Compare with [Burp Suite](burp-suite.md): ZAP is free and open, Burp Pro's
  scanner is generally stronger for deep manual work.
- Docs: https://www.zaproxy.org/docs/
