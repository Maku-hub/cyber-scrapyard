# WPScan

> WordPress-focused security scanner: enumerates users, plugins and themes, and
> flags known vulnerabilities in them from a maintained database.

- **Link:** https://github.com/wpscanteam/wpscan (site: https://wpscan.com)
- **Type:** freemium (tool open source; vuln database needs a free API token)
- **Platform:** cross-platform (Ruby)

## Description

WordPress powers a huge share of the web, and its plugins/themes are a frequent
source of vulnerabilities. WPScan fingerprints a WordPress install and
enumerates its users, installed plugins and themes, then cross-references them
against a known-vulnerability database. That makes it the standard first tool
when you find a WordPress target.

## Installation

```bash
# Debian/Kali package
sudo apt install wpscan

# Or install the gem
gem install wpscan
```

## Usage examples

```bash
# Enumerate users (useful for later brute-force / password spraying)
wpscan --url chuckkeith.com --enumerate u

# Enumerate installed plugins
wpscan --url chuckkeith.com --enumerate p

# Aggressively enumerate vulnerable plugins (vp) and themes (vt)
wpscan --url http://example.com --enumerate vp,vt --plugins-detection aggressive

# Include the vulnerability data (needs a free token from wpscan.com)
wpscan --url https://target.example.com --api-token <YOUR_TOKEN>

# Password-guess against a discovered user with a wordlist
wpscan --url https://target.example.com -U admin -P /usr/share/wordlists/rockyou.txt
```

## Notes & references

- Get a **free API token** at https://wpscan.com to receive CVE details in
  results; without it you still get enumeration but no vuln matching.
- Enumeration modes: `u` (users), `p`/`vp` (all/vulnerable plugins),
  `t`/`vt` (all/vulnerable themes). Aggressive detection finds more but is
  louder.
- Feed discovered users into [Hydra](../password-cracking/) or WPScan's own
  `-P` brute force — authorized targets only.
- Docs: https://github.com/wpscanteam/wpscan/wiki
