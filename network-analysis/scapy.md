# Scapy

> A Python library and interactive shell for crafting, sending, sniffing, and
> dissecting packets — build almost any protocol stack layer by layer.

- **Link:** https://github.com/secdev/scapy
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

Scapy is a packet manipulation swiss army knife. It's libpcap-compatible and
lets you forge packets at any layer, send them, capture responses, and script
dynamic reactions to network events — think a programmable, interactive version
of [tshark](tshark.md) that you drive from Python. It's ideal for custom port
scanners, protocol testing, ARP experiments, and pulling apart pcap files. Use
it only against systems you own or are authorized to test.

## Installation

```bash
sudo apt install python3-scapy   # or: pipx install scapy
sudo scapy                       # start the interactive shell (root for raw sockets)
```

## Usage examples

### Help & introspection

```python
ls()          # list supported protocols/layers
ls(ICMP)      # show fields of a specific layer
lsc()         # list Scapy commands
help(sniff)   # docs for any function
```

### Build and send a packet

```python
# Stack layers with "/": an IP packet carrying an ICMP echo
pkt = IP(dst='192.168.0.1')/ICMP()
pkt.show()               # display the crafted packet
reply = sr1(pkt)         # send one packet, receive one answer
reply.show()
```

### Send multiple packets

```python
# ICMP sweep across message types, sr() returns answered + unanswered
pkts = IP(dst='10.0.1.254')/ICMP(type=(0,20))
ans, unans = sr(pkts, timeout=2)
ans.show()
```

### TCP port scan

```python
# SYN scan of ports 1-100; a SYN/ACK ("SA") means the port is open
res, unans = sr(IP(dst="10.0.0.11")/TCP(flags="S", dport=(1,100)), timeout=10)
for snd, rcv in res:
    if rcv[TCP].flags == "SA":
        print(f"Open port: {snd[TCP].dport}")
```

### Sniff ARP traffic

```python
# Print a message for every ARP request seen on ens4
def process_arp(packet):
    if packet.haslayer(ARP):
        print(f"{packet[ARP].psrc} is asking where {packet[ARP].pdst} is")
        packet.show()

sniff(filter="arp", prn=process_arp, store=0, iface="ens4")
```

### Working with pcap files

```python
pkts = rdpcap('www_request.pcap')   # read a capture written by tcpdump/Wireshark
hexdump(pkts[3])                    # hex dump of the 4th packet
pkts[3].show()                      # dissect it
```

## Notes & references

- Raw packet crafting/sniffing needs root (Linux) or admin + Npcap (Windows).
- `sr()` returns `(answered, unanswered)`, `sr1()` returns just the first
  answer, `send()`/`sendp()` transmit at layer 3 / layer 2 without waiting.
- ARP-spoofing primitives (`ARP(op=2, ...)`, `getmacbyip()`) exist in Scapy;
  only use them in an authorized lab — see [Ettercap & Bettercap](ettercap-bettercap.md).
- Docs & tutorial: https://scapy.readthedocs.io/en/latest/usage.html
- TCP scanning guide: https://scapy.readthedocs.io/en/latest/usage.html#tcp-port-scanning
