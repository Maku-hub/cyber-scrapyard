# tcpdump

> The classic lightweight CLI packet capture tool: grab traffic on any
> interface, write it to a pcap, and filter with BPF expressions.

- **Link:** https://www.tcpdump.org
- **Type:** open source
- **Platform:** cross-platform (Linux/macOS/BSD; `WinDump` on Windows)

## Description

tcpdump is on almost every Unix box, which makes it the go-to for a quick
capture when you can't (or don't want to) run a GUI. You point it at an
interface, optionally add a BPF filter to keep the noise down, and either watch
packets scroll by or write them to a `.pcap` for later analysis in
[Wireshark](wireshark.md) or [Scapy](scapy.md). Small, fast, and scriptable.

## Installation

```bash
sudo apt install tcpdump     # Debian/Kali/Ubuntu
```

## Usage examples

```bash
# Capture ICMP on every interface (spot ping sweeps / network mapping)
tcpdump -i any icmp

# Capture all traffic on eth0 and write it to a pcap file
tcpdump -w capture.pcap -i eth0

# Read and display packets from a saved pcap (offline analysis)
tcpdump -r capture_file.pcap

# Capture the first 100 packets on eth0, then stop
tcpdump -i eth0 -c 100

# Verbose capture with ASCII payload, no name resolution
tcpdump -i ens4 -n -A -vv

# Filter by host and port (RIP traffic on udp/520 here)
tcpdump -i ens4 host 10.0.0.11 and port 520

# Combine conditions
tcpdump -i ens4 host 10.0.0.11 and "port 520 or port 22"

# TCP to/from one host, save 10 packets to a pcap for Scapy/Wireshark
tcpdump -n -i ens4 -w dump.pcap -c 10 tcp and host 10.0.0.11
```

### Useful flags

```text
-n            disable DNS lookups (without it tcpdump often looks "frozen")
-i <iface>    listen on a specific interface
-c N          stop after N packets
-w file.pcap  write raw packets to a file
-r file.pcap  read and display packets from a file
-vv           more verbose packet detail
-X / -XX      also show payload as a hex dump
-e            show link-layer (MAC) addresses
```

### BPF capture filters

```text
host 192.168.1.1          # traffic to or from a host
dst host 192.168.1.1      # only to a destination
port 80                   # a specific port
arp / tcp / icmp / ip     # by protocol
# Combine them:
host 192.168.1.1 and dst port 25
# Logical grouping:
tcp and (port 80 or port 25)
```

## Notes & references

- BPF filters (`host`, `port`, `tcp`…) are the *same* language tshark uses with
  `-f` — but different from Wireshark's display filters.
- Always add `-n` unless you specifically want reverse-DNS; it removes a big
  source of latency and accidental lookups.
- Rotate large captures with `-C <MB>` and `-W <count>` to cap disk usage.
- Manual & filter syntax (`man pcap-filter`): https://www.tcpdump.org/manpages/
