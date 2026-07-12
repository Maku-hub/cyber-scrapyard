# ngrep

> "grep for the network": match a regex or string against live packet payloads
> or a pcap — quick way to spot cleartext data without a full analyzer.

- **Link:** https://github.com/jpr5/ngrep
- **Type:** open source
- **Platform:** cross-platform (Linux/macOS/BSD/Windows)

## Description

ngrep applies grep-style pattern matching to packet payloads. When you just
want to know "is the word *password* crossing this interface?" or "show me every
HTTP request containing `/admin`", ngrep is faster to type than opening
[Wireshark](wireshark.md). It combines BPF capture filters (like
[tcpdump](tcpdump.md)) with a payload regex, printing matching packets in a
readable form.

## Installation

```bash
sudo apt install ngrep       # Debian/Kali/Ubuntu
```

## Usage examples

```bash
# Match a string in any packet payload on eth0 (-d selects the interface)
ngrep -d eth0 "password"

# Case-insensitive (-i) HTTP GET/POST requests, quiet header output (-q -W byline)
ngrep -d eth0 -i -q -W byline "^(GET|POST) " tcp port 80

# Search a saved capture instead of a live interface (-I reads a pcap)
ngrep -I capture.pcap "Authorization:"

# Match a User-Agent regex on any host, showing timestamps (-t)
ngrep -d any -t "User-Agent:.*curl" tcp port 80
```

## Notes & references

- The last argument is a **BPF filter** (`tcp port 80`, `host x`) — same syntax
  as tcpdump; the quoted pattern before it is the payload regex.
- `-W byline` renders `\r\n` as real line breaks, which makes HTTP/SMTP readable.
- Great for catching credentials in cleartext protocols during authorized tests;
  useless against TLS-encrypted payloads (use [mitmproxy](mitmproxy.md) there).
- `-x` shows a hex+ASCII dump for binary protocols.
