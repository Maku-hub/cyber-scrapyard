# ModSecurity

> The open-source web application firewall (WAF) engine: inspects HTTP requests
> and responses against rules to block SQLi, XSS, and other web attacks.

- **Link:** https://github.com/owasp-modsecurity/ModSecurity
- **Type:** open source
- **Platform:** cross-platform (module for Apache, Nginx, IIS)

## Description

ModSecurity is a WAF that plugs into your web server (or runs standalone via
libmodsecurity + a connector) and evaluates every request against a rule set
before it reaches the application. On its own the engine does little; the value
comes from the **OWASP Core Rule Set (CRS)**, a maintained collection of generic
rules that catch injection, cross-site scripting, protocol violations, scanners,
and more. You can run it in detection-only mode first to tune out false
positives, then flip to blocking.

## Installation

```bash
# Nginx connector + engine on Debian/Ubuntu
sudo apt install libnginx-mod-http-modsecurity
```

```bash
# Fetch the OWASP Core Rule Set
git clone https://github.com/coreruleset/coreruleset /etc/nginx/modsec/crs
```

## Usage examples

```nginx
# Enable ModSecurity for a server block and load the main rules file (Nginx)
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

```apache
# Turn the rules engine fully on (blocking) — use DetectionOnly while tuning
SecRuleEngine On

# Custom rule: block requests whose query string contains a naive SQLi marker
SecRule ARGS "@rx (?i:union\s+select)" "id:1001,phase:2,deny,status:403,msg:'SQLi attempt'"
```

```bash
# Watch the audit log to see which rules fire (and tune false positives)
tail -f /var/log/modsec_audit.log
```

## Notes & references

- Start in `SecRuleEngine DetectionOnly`, review the audit log, add exclusions,
  then switch to `On`. Blocking untuned CRS in production will break apps.
- OWASP CRS: https://github.com/coreruleset/coreruleset
- Reference manual: https://github.com/owasp-modsecurity/ModSecurity/wiki
- A WAF is defence-in-depth, not a fix — pair it with secure coding and testing
  from [Web Application Security](../web-app-security/).
