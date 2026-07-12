# NetworkMiner

> A passive network forensic tool (NFAT) that reads a pcap and reconstructs the
> interesting bits for you — hosts, files, images, credentials, and sessions —
> without touching the network itself.

- **Link:** https://www.netresec.com/?page=NetworkMiner
- **Type:** freemium (free edition is closed-source but no-cost; paid Professional adds features)
- **Platform:** Windows (native); Linux/macOS via Mono

## Description

NetworkMiner takes a different angle from [Wireshark](wireshark.md): instead of a
packet-by-packet view, it parses a capture and organises what it finds by *host*
and *artifact*. It carves transferred files out of HTTP/FTP/SMB/TFTP streams,
extracts images, pulls cleartext (and some hashed) credentials, reassembles
messages, and fingerprints operating systems — all passively, so it's safe to run
against evidence pcaps during forensics and incident response. The free edition
is more than enough for file and credential carving; it's a fast way to answer
"what was exfiltrated / who logged in?" from a capture.

## Installation

```bash
# Download the free edition zip from netresec.com, then on Linux/macOS run via Mono
sudo apt install mono-runtime libmono-system-windows-forms4.0-cil
unzip NetworkMiner_*.zip -d NetworkMiner && cd NetworkMiner
mono NetworkMiner.exe
```

## Typical workflow

1. **Open a capture** — `File -> Open` a `.pcap`/`.pcapng`, or start a live
   capture on Windows (live sniffing is best done with
   [tcpdump](tcpdump.md)/Wireshark and then imported).
2. **Hosts tab** — review each detected host: OS guess, open ports, sent/received
   files, and hostnames. This is the "who was talking" overview.
3. **Files / Images tabs** — every carved file lands on disk in the
   `AssembledFiles` folder; sort by frame or host and open them directly.
4. **Credentials tab** — inspect harvested logins (HTTP basic/forms, FTP, IMAP,
   Kerberos/NTLM hashes) captured in the traffic.
5. **Messages / Parameters / DNS tabs** — read reconstructed emails/chats and
   review extracted parameters and DNS lookups for indicators.

## Notes & references

- Purely passive and read-only on the capture — a good habit for preserving
  evidence integrity in [forensics/IR](../forensics-ir/) work.
- Pairs naturally with the rest of this category: capture with
  [tcpdump](tcpdump.md), triage artifacts in NetworkMiner, then dig into packets
  in [Wireshark](wireshark.md) when you need protocol detail.
- Netresec also publishes CapLoader (large-pcap triage) and sample capture files
  for practice: https://www.netresec.com/?page=PcapFiles
- The extracted-hashes output feeds offline cracking with
  [hashcat](../password-cracking/hashcat.md) / [John](../password-cracking/john-the-ripper.md).
