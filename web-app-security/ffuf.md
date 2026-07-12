# ffuf

> "Fuzz Faster U Fool" — a blazing-fast web fuzzer in Go for directory/file
> discovery, virtual-host brute forcing, and parameter/value fuzzing.

- **Link:** https://github.com/ffuf/ffuf
- **Type:** open source
- **Platform:** cross-platform (Go)

## Description

ffuf replaces the keyword `FUZZ` anywhere in a request with entries from a
wordlist and reports how the server responds. That simple idea covers a lot:
brute-forcing hidden directories and files, enumerating virtual hosts, fuzzing
GET/POST parameters, and testing values. Its speed and rich filtering
(by status code, size, word count, or regex) make it a go-to for web content
discovery.

## Installation

```bash
# Debian/Kali package
sudo apt install ffuf

# Or install with Go
go install github.com/ffuf/ffuf/v2@latest
```

## Usage examples

```bash
# Directory/file discovery — FUZZ marks the injection point
ffuf -u https://target.example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Filter out a noisy status code (e.g. 302 redirects) with -fc
ffuf -u https://10.10.0.7:8080/FUZZ -fc 302 -w /usr/share/wordlists/dirb/common.txt

# Only show matching codes instead (-mc), and follow redirects
ffuf -u https://target.example.com/FUZZ -w wordlist.txt -mc 200,301 -r

# Fuzz with an authorization header (e.g. Basic auth from captured creds)
ffuf -u https://target.example.com/FUZZ -w wordlist.txt \
  -H "Authorization: Basic Z3JlZW5jYXQ6aW50aGVmb3Jlc3Q="

# Filter by response size to hide a constant "not found" page (-fs)
ffuf -u https://target.example.com/FUZZ -w wordlist.txt -fs 1256

# Virtual-host discovery — fuzz the Host header
# First note the default-vhost response size, then filter it out with -fs <size>
ffuf -u https://target.example.com/ -w subdomains.txt \
  -H "Host: FUZZ.target.example.com" -fs <baseline-size>

# POST parameter fuzzing
ffuf -u https://target.example.com/login -X POST \
  -d "username=admin&password=FUZZ" -w passwords.txt -fc 401
```

## Notes & references

- Match/filter flags are the core skill: `-mc/-fc` (status code),
  `-ms/-fs` (size), `-mw/-fw` (words), `-mr/-fr` (regex). Calibrate filters
  against a known-bad response first.
- Add file extensions with `-e .php,.txt,.bak`, and recurse with
  `-recursion -recursion-depth 2`.
- Great wordlists live in **SecLists** (`sudo apt install seclists`), e.g.
  `Discovery/Web-Content/`.
- Related tools: [gobuster](gobuster.md), [feroxbuster](feroxbuster.md),
  [wfuzz & friends](wfuzz-and-fuzzers.md).
- Docs: https://github.com/ffuf/ffuf/wiki
