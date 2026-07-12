# ProxyChains

> Force almost any TCP tool through a chain of SOCKS/HTTP proxies — the standard
> way to pivot scanners and clients through an SSH tunnel into an internal network.

- **Link:** https://github.com/rofl0r/proxychains-ng
- **Type:** open source
- **Platform:** Linux / macOS (proxychains-ng is the maintained fork)

## Description

ProxyChains hooks a program's network calls and routes them through one or more
proxies. The classic pentest use case: you have SSH access to a jump host inside
the target network, so you open a dynamic SOCKS proxy with `ssh -D`, then run
[Nmap](../recon-scanning/nmap.md), a browser, or any TCP client "through"
proxychains to reach hosts you otherwise couldn't. It turns a single foothold
into a pivot into the internal LAN. Use only where you're authorized to pivot.

## Installation

```bash
sudo apt install proxychains4   # provides proxychains-ng (config: /etc/proxychains4.conf)
```

## Usage examples

```bash
# 1. Configure the SOCKS proxy proxychains should use
nano /etc/proxychains4.conf
# At the end of the file, under [ProxyList], replace the default line with:
#   socks5  127.0.0.1 1080

# 2. Open a dynamic SSH tunnel (SOCKS proxy on local port 1080) into the network
ssh -D 1080 <user>@<jump-host>

# 3. Now route tools through the tunnel to reach the internal LAN
proxychains nmap 10.10.0.0/24

# TCP-connect scan through the proxy, no ping, saving XML
# (SOCKS can't carry raw/SYN scans, so -sT and -Pn are required)
proxychains nmap -Pn -sT 10.10.0.0/24 -oX nmap_internal.xml
```

## Notes & references

- SOCKS proxies only carry **TCP** connections. That's why you must use Nmap's
  connect scan (`-sT`) and skip host discovery (`-Pn`) — SYN scans, UDP, and
  ICMP won't traverse the tunnel.
- Config lives at `/etc/proxychains4.conf` (older docs say `proxychains.conf`);
  `dynamic_chain` tolerates dead proxies, `strict_chain` requires all in order.
- `proxy_dns` in the config routes DNS through the tunnel too — leave it on to
  avoid leaking internal hostname lookups.
- Pairs naturally with SSH pivoting; see [../exploitation-c2/](../exploitation-c2/)
  for C2-based pivoting alternatives.
