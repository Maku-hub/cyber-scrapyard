# Gobuster

> Fast directory/file, DNS subdomain, and virtual-host brute-forcer written in
> Go — a classic first step in web content and DNS discovery.

- **Link:** https://github.com/OJ/gobuster
- **Type:** open source
- **Platform:** cross-platform (Go)

## Description

Gobuster brute-forces things a web server or DNS won't tell you about. Its
subcommands cover the common cases: `dir` finds hidden directories and files,
`dns` enumerates subdomains, and `vhost` discovers virtual hosts served from the
same IP. It's simple, fast, and reliable — often the tool you run right after a
port scan to map a web app's structure.

## Installation

```bash
# Debian/Kali package
sudo apt install gobuster

# Or install with Go
go install github.com/OJ/gobuster/v3@latest
```

## Usage examples

```bash
# dir mode — brute-force directories and files with a wordlist
gobuster dir -u https://target.example.com \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt

# dir mode with extensions and more threads
gobuster dir -u https://target.example.com -w wordlist.txt -x php,txt,html -t 50

# dns mode — enumerate subdomains of a domain
gobuster dns -d target.example.com -w dns-jhaddix.txt

# vhost mode — find virtual hosts on the same server
gobuster vhost -u https://target.example.com -w subdomains.txt --append-domain
```

## Notes & references

- Grab wordlists from **SecLists** (`sudo apt install seclists`); for DNS the
  classic list is `Discovery/DNS/dns-Jhaddix.txt`.
- Useful `dir` flags: `-x` (extensions), `-s`/`-b` (status whitelist/blacklist),
  `-k` (skip TLS verification), `-c` (send cookies for authenticated scans).
- For recursion and prettier live output, try [feroxbuster](feroxbuster.md);
  for arbitrary request fuzzing, [ffuf](ffuf.md).
- For broader subdomain discovery combine with passive tools —
  see [../recon-scanning/](../recon-scanning/) (subfinder, amass).
- Docs: https://github.com/OJ/gobuster#readme
