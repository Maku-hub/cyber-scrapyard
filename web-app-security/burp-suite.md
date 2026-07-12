# Burp Suite

> The de facto intercepting proxy and toolkit for web application testing:
> capture, inspect, replay and fuzz HTTP(S) traffic, and (in Pro) run an
> automated scanner against the same target.

- **Link:** https://portswigger.net/burp
- **Type:** freemium (Community free / Professional & Enterprise commercial)
- **Platform:** cross-platform (Java)

## Description

Burp Suite sits between your browser and the target as a man-in-the-middle
proxy, letting you see and modify every request and response. It's the tool most
web testers live in: intercept a login, tamper with a parameter, replay a
request with a tweaked value, or blast an endpoint with a wordlist. The
**Community** edition is free and includes the Proxy, Repeater, Decoder,
Comparer and a rate-limited Intruder; **Professional** adds the automated web
vulnerability scanner, a full-speed Intruder, session handling, and the BApp
extension store.

## Installation

```bash
# Debian/Kali ships a packaged build
sudo apt install burpsuite

# Or download the cross-platform installer / JAR from PortSwigger
# https://portswigger.net/burp/releases
```

## Usage examples

Burp is GUI-driven; the "commands" below are the workflow you follow inside it.

```text
# 1. Proxy — intercept and edit traffic
#    Set your browser proxy to 127.0.0.1:8080 (or use the built-in Chromium),
#    install Burp's CA cert (http://burp) so HTTPS is decrypted,
#    then Proxy > Intercept toggles catching requests before they're sent.

# 2. Repeater — manually replay & tweak one request
#    Right-click a request > "Send to Repeater", edit any part
#    (headers, body, params), hit Send, and read the raw response.

# 3. Intruder — automated request fuzzing
#    "Send to Intruder", mark payload positions (§ markers), load a wordlist,
#    and run. Attack types: Sniper (one position), Cluster bomb (all combos).
#    Sort results by status code / response length to spot anomalies.

# 4. Scanner (Pro only) — automated vuln detection
#    Right-click a target > "Scan", pick crawl-and-audit, review the issues
#    (SQLi, XSS, SSRF, misconfig …) with request/response evidence.
```

```bash
# Headless / CI: drive Burp Pro or the Enterprise scanner via its REST API
# and burp-rest-api / official CLI runners (see docs for the endpoint schema).
curl -X POST http://127.0.0.1:1337/v0.1/scan -d '{"urls":["https://target"]}'
```

## Notes & references

- Free alternative with a similar model: [OWASP ZAP](owasp-zap.md) — fully open
  source and scriptable, better suited to CI pipelines.
- Extend Burp via the **BApp Store** (Logger++, Autorize, Param Miner, Turbo
  Intruder). Community edition supports extensions but not the scanner.
- Community Intruder is throttled — for heavy fuzzing use [ffuf](ffuf.md) or
  [feroxbuster](feroxbuster.md) alongside Burp.
- Learn hands-on for free at PortSwigger's **Web Security Academy**:
  https://portswigger.net/web-security — cross-linked from
  [../learning-resources/](../learning-resources/).
- Docs: https://portswigger.net/burp/documentation
