# Wireshark

> The de facto graphical packet analyzer: capture live traffic or open a pcap
> and drill into every protocol layer with powerful display filters.

- **Link:** https://www.wireshark.org
- **Type:** open source
- **Platform:** cross-platform (`tshark` is the CLI counterpart, `dumpcap` the capture backend)

## Description

Wireshark is the tool you reach for when you need to *see* what's on the wire.
It dissects hundreds of protocols, colorizes traffic, reassembles TCP streams,
and lets you slice a capture with expressive display filters. It's equally at
home in troubleshooting (why is this handshake failing?), blue-team analysis
(what did that host talk to?), and offensive work (extracting credentials or
tokens from cleartext protocols). For headless or scripted work, use its CLI
sibling [tshark](tshark.md).

## Installation

```bash
sudo apt install wireshark   # Debian/Kali/Ubuntu (add your user to the "wireshark" group)
```

## Usage examples

Wireshark is GUI-driven, so most work happens through **display filters** typed
into the filter bar (these differ from BPF capture filters used by
[tcpdump](tcpdump.md)).

```text
# Show only traffic to/from one host
ip.addr == 192.168.1.10

# HTTP GET requests only
http.request.method == "GET"

# DNS queries
dns.flags.response == 0

# TCP SYN packets (connection attempts) with no ACK
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Traffic on a specific port
tcp.port == 443

# Find cleartext passwords in HTTP form posts
http.request.method == "POST" && frame contains "password"

# Combine conditions
ip.src == 10.0.0.5 && (tcp.port == 80 || tcp.port == 443)
```

### Common workflows

- **Follow a stream:** right-click a packet → *Follow → TCP/HTTP/TLS Stream* to
  reconstruct an entire conversation as readable text.
- **Statistics → Conversations / Endpoints:** see who talked to whom and how
  much data moved — quick way to spot beaconing or exfiltration.
- **Statistics → Protocol Hierarchy:** breakdown of protocols in the capture.
- **File → Export Objects → HTTP:** pull transferred files (images, binaries,
  documents) straight out of a capture.
- **Right-click → Apply as Filter:** build filters from a field without typing.

## Notes & references

- Capture filters (BPF, set *before* capture) and display filters (set *after*)
  use different syntax — a frequent source of confusion.
- Capturing usually needs root/admin; on Linux prefer adding your user to the
  `wireshark` group over running the GUI as root.
- Official display-filter reference: https://www.wireshark.org/docs/dfref/
- Sample captures for practice: https://wiki.wireshark.org/SampleCaptures
- For live SIEM/IDS context on suspicious flows, see
  [../defense-blueteam/](../defense-blueteam/).
