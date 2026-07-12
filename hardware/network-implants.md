# Network Implants

> Small drop-in devices you place inline on a wired network (or between a device
> and its display) to capture traffic, tap connections, run recon payloads, and
> phone home for remote access.

- **Link:** https://hak5.org
- **Type:** commercial (hardware)
- **Platform:** deployed against Ethernet networks / HDMI displays

## Description

Network implants trade the flashy exploit for physical position. Slip one inline
on an Ethernet run or a monitor cable during authorized physical access, and it
quietly captures data or gives you a foothold from the inside — often the most
reliable path in a red-team engagement. They range from passive taps that just
copy traffic to active implants that establish a remote tunnel back to you.

## Devices worth knowing

| Device | What it does |
| --- | --- |
| **Packet Squirrel** | Inline Ethernet implant for man-in-the-middle capture, VPN tunneling, and remote access |
| **Shark Jack** | Fast, payload-driven network recon device — plug into a port and it runs a scripted scan/attack |
| **Plunder Bug** | Compact "smart" LAN tap/sniffer that copies traffic to your machine or phone |
| **Screen Crab** | Inline HDMI implant that captures screenshots of a target display and exfiltrates them over the network |

## Usage examples

```bash
# Packet Squirrel — a payload can be as simple as tcpdump to USB storage
tcpdump -i eth0 -w /mnt/loot/capture.pcap

# ...or set up a reverse tunnel back to your server for remote access
```

## Notes & references

- All four are **Hak5** devices: https://hak5.org — they share the same payload
  ecosystem and a microSD-based deployment model.
- Passive taps (Plunder Bug) are lower-risk to drop than active inline implants
  (Packet Squirrel), which briefly interrupt the link when inserted.
- Analyze whatever you capture with tools from
  [Network Traffic Analysis](../network-analysis/) (Wireshark, tcpdump).
- A dedicated **network tap** such as the Dualcomm USB-powered tap is a
  vendor-neutral alternative for lab capture:
  https://www.dualcomm.com
