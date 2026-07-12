# feroxbuster

> A fast, recursive content-discovery tool in Rust — like gobuster's `dir` mode
> but recurses automatically and gives clean, live output.

- **Link:** https://github.com/epi052/feroxbuster
- **Type:** open source
- **Platform:** cross-platform (Rust)

## Description

feroxbuster brute-forces directories and files, and its standout feature is
sensible **automatic recursion**: when it finds a directory it keeps digging
into it without you re-running the tool. It's fast, has smart response filtering,
resumes interrupted scans, and produces readable output — a strong default for
mapping a web app's directory tree.

## Installation

```bash
# Debian/Kali package
sudo apt install feroxbuster

# Or install with Cargo
cargo install feroxbuster
```

## Usage examples

```bash
# Basic recursive scan
feroxbuster -u https://target.example.com

# Custom wordlist, add extensions, cap recursion depth
feroxbuster -u https://target.example.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,txt,bak --depth 2

# Filter out responses by status code or size (-C / -S)
feroxbuster -u https://target.example.com -C 404,403 -S 0

# Authenticated scan with a header + skip TLS verification
feroxbuster -u https://target.example.com -H "Cookie: session=abc123" -k
```

## Notes & references

- Recursion is on by default — use `--depth` to bound it, or `-n` to disable.
- `--resume-state` / `--auto-tune` make long scans robust; output to a file with
  `-o results.txt`.
- Pairs well with [gobuster](gobuster.md) and [ffuf](ffuf.md); choose feroxbuster
  when you want painless recursion.
- Docs: https://epi052.github.io/feroxbuster-docs/
