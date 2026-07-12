# hping3

> A command-line packet generator and analyzer: craft custom TCP/UDP/ICMP
> packets for firewall testing, traceroute, and stress/DoS simulation.

- **Link:** https://github.com/antirez/hping
- **Type:** open source
- **Platform:** Linux (also builds on other Unix-like systems)

## Description

hping3 lets you assemble and send arbitrary TCP, UDP, ICMP, and raw-IP packets,
then reports on the replies. It's used to probe firewall rules, perform
advanced traceroutes over TCP/UDP (useful where ICMP is blocked), test how a
host holds up under a flood, and spoof source addresses. Where
[Scapy](scapy.md) gives you programmable flexibility, hping3 is a fast
one-liner for the common cases. Flooding and spoofing must be confined to
systems you own or are authorized to test.

## Installation

```bash
sudo apt install hping3      # Debian/Kali/Ubuntu
```

## Usage examples

```bash
# SYN flood simulation against port 80 (-S SYN, --flood max rate, -V verbose)
hping3 -S --flood -V -p 80 172.18.0.11

# TCP-less traceroute using ICMP echo (-1), verbose — map the path to a host
hping3 --traceroute -V -1 example.com

# Send a UDP packet to a specific port
hping3 --udp -p 19 10.0.0.11

# SYN with 1000-byte payload, 5 packets, randomized source IPs (-c count -d data)
hping3 -S -V -p 80 -d 1000 -c 5 --rand-source ships.securitum.space

# Same, but fragment the packet (-f) to test how the target/firewall reassembles
hping3 -S -V -p 80 -d 1000 -c 5 --rand-source ships.securitum.space -f
```

## Notes & references

- `--rand-source` spoofs a different source IP per packet, which makes
  filtering/attribution harder — a classic reason it appears in DoS testing.
- Common flags: `-S/-A/-F/-P/-U` set TCP flags, `-p` destination port,
  `-c` packet count, `-d` payload size, `-i uN` interval in microseconds.
- Requires root for raw sockets.
- For detecting/blocking this kind of traffic, see
  [../defense-blueteam/](../defense-blueteam/).
