# Network Traffic Analysis

Tools for capturing, inspecting, crafting, and manipulating network traffic —
from passive packet analysis to active man-in-the-middle work. This is where you
figure out *what's actually on the wire*: debugging a protocol, reconstructing a
session, hunting for cleartext credentials, or pivoting through a network.

## Tools

| Tool | Summary |
| --- | --- |
| [Wireshark](wireshark.md) | The de facto GUI packet analyzer — display filters, follow stream, protocol dissection |
| [tshark](tshark.md) | CLI Wireshark — filter, dissect, and extract fields from captures in scripts |
| [tcpdump](tcpdump.md) | Lightweight CLI capture: write/read pcaps and filter with BPF expressions |
| [Scapy](scapy.md) | Python packet crafting & sniffing — build any protocol layer by layer |
| [Netcat (nc)](netcat.md) | TCP/IP swiss army knife — listeners, connect, transfer, banner grab, shells |
| [hping3](hping3.md) | Custom packet generator for firewall testing, traceroute, and flood simulation |
| [ngrep](ngrep.md) | grep for network traffic — regex-match live or captured packet payloads |
| [ProxyChains](proxychains.md) | Tunnel TCP tools through SOCKS/SSH to pivot into internal networks |
| [Ettercap & Bettercap](ettercap-bettercap.md) | MITM / ARP-spoofing suites for LAN interception (authorized use) |
| [dsniff & arpspoof](dsniff-arpspoof.md) | Classic sniffing suite — ARP-poison, then harvest cleartext creds, URLs, and files |
| [Zeek](zeek.md) | Network security monitor — turns traffic into rich per-protocol logs for hunting |
| [NetworkMiner](networkminer.md) | Passive pcap forensics — carve files, images, and credentials by host |
| [mitmproxy](mitmproxy.md) | Interactive, scriptable HTTPS MITM proxy for inspecting and modifying web traffic |
| [ike-scan](ike-scan.md) | Discover and fingerprint IPsec VPN gateways over IKE (UDP/500) |
| [Arkime](arkime.md) | Large-scale full-packet capture with indexed session search and a web UI |

## Capture vs. display filters

Two filter languages show up constantly and are easy to mix up:

- **BPF capture filters** (`host`, `port`, `tcp`, `icmp`) are applied *before*
  capture by [tcpdump](tcpdump.md), tshark `-f`, ngrep, and Wireshark's capture
  dialog. They keep noise (and disk usage) down on busy links.
- **Display filters** (`ip.addr ==`, `http.request.method ==`) are applied
  *after* capture by [Wireshark](wireshark.md) and tshark `-Y`. They're richer
  but only narrow what you *see*, not what was recorded.

## Typical workflow

1. **Capture** — `tcpdump -i eth0 -w capture.pcap` on the box that sees the
   traffic (or a SPAN/mirror port).
2. **Analyze** — open the pcap in Wireshark, or triage in the terminal with
   `tshark -qz` statistics and `ngrep`.
3. **Extract** — follow TCP streams, export transferred objects, pull fields
   with `tshark -T fields`.
4. **Craft / replay** — reproduce or fuzz traffic with [Scapy](scapy.md) or
   [hping3](hping3.md).
5. **Intercept (authorized)** — MITM with [Ettercap/Bettercap](ettercap-bettercap.md)
   or [mitmproxy](mitmproxy.md), then loop back to capture and analysis.

> ⚠️ Sniffing and MITM touch other people's data. Only run these on networks you
> own or are explicitly authorized to test.

See also: [Defensive Security & Blue Team](../defense-blueteam/) for detecting
this activity (IDS/IPS, ARP inspection), and [Active Directory](../active-directory/)
for AD-specific relay and poisoning attacks.
