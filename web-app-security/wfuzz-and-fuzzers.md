# wfuzz & dirsearch

> A pair of classic web content/parameter fuzzers. Grouped here because they
> overlap heavily with [ffuf](ffuf.md) and [gobuster](gobuster.md) — reach for
> whichever is already installed or fits the task.

- **Links:** https://github.com/xmendez/wfuzz ·
  https://github.com/maurosoria/dirsearch
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

Before ffuf and feroxbuster became the defaults, **wfuzz** was a staple web
fuzzer, and **dirsearch** remains popular for quick directory brute-forcing with
sane defaults. Both do content/parameter discovery; the differences are speed
and ergonomics. wfuzz is the most flexible (fuzz any part of a request, multiple
payload markers); dirsearch is a batteries-included Python directory scanner.

## Installation

```bash
# Debian/Kali packages
sudo apt install wfuzz dirsearch
```

## Usage examples

```bash
# dirsearch — quick directory scan with common extensions
dirsearch -u https://target.example.com -e php,txt,html

# wfuzz — directory discovery, hiding 404 responses (--hc)
wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 404 https://target.example.com/FUZZ

# wfuzz — brute-force a login POST, hiding a known failure length (--hh)
wfuzz -w passwords.txt --hh 1256 \
  -d "user=admin&pass=FUZZ" https://target.example.com/login

# wfuzz — fuzz a GET parameter value
wfuzz -w values.txt --hc 404 "https://target.example.com/item?id=FUZZ"
```

## Notes & references

- wfuzz filters mirror ffuf: `--hc/--sc` (status), `--hh/--sh` (chars),
  `--hl/--sl` (lines), `--hw/--sw` (words). Calibrate against a known response.
- For most new work [ffuf](ffuf.md) (speed) or [feroxbuster](feroxbuster.md)
  (recursion) are better first picks; keep these for when they're preinstalled
  or you like their syntax.
- Wordlists: **SecLists** (`sudo apt install seclists`) and the bundled
  `/usr/share/wordlists/dirb/` on Kali.
