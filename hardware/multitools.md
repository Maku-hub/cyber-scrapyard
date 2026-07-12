# Multitools

> Swiss-army hardware that spans many protocols and roles in one device — from
> the pocket-sized Flipper Zero to specialized side-channel and sub-GHz rigs.

- **Link:** https://flipperzero.one
- **Type:** ranges from open hardware to commercial
- **Platform:** cross-platform companion apps

## Description

These are the "do a bit of everything" devices. Some, like the Flipper Zero,
bundle sub-GHz radio, RFID, NFC, IR, and GPIO into one playful package with a
huge community. Others are purpose-built but flexible within their niche —
capturing Wi-Fi handshakes autonomously, replaying RF signals, or probing chips
for side-channel leaks. Great for learning across domains and for quick field
work where carrying a bag of single-purpose tools isn't practical.

## Devices worth knowing

| Device | What it does |
| --- | --- |
| **Flipper Zero** | Multi-protocol pocket tool: sub-GHz, 125 kHz RFID, NFC, infrared, GPIO/hardware hacking, plus a massive add-on ecosystem |
| **Pwnagotchi** | An AI-flavored, Raspberry Pi-based gadget that roams and captures WPA/WPA2 handshakes for offline cracking |
| **PandwaRF** | Sub-GHz RF tool for capture, analysis, and replay of signals (key fobs, remotes) from a phone |
| **ChipWhisperer** | Hardware-hacking and **side-channel analysis** platform (power analysis, voltage/clock glitching) for embedded security |

## Usage examples

```text
# Flipper Zero — read then emulate a sub-GHz remote via the on-device menu:
#   Sub-GHz  ->  Read  ->  (capture)  ->  Save  ->  Emulate

# Pwnagotchi runs headless; handshakes land in /root/handshakes as .pcap,
# ready for hashcat / aircrack-ng offline.
```

## Notes & references

- **Flipper Zero:** https://flipperzero.one — the community firmware and app
  catalog dramatically extend the stock capabilities.
- **Pwnagotchi:** https://pwnagotchi.ai — pairs naturally with the
  [Wi-Fi & Wireless](../wifi-wireless/) cracking workflow and
  [Password Cracking & Hashing](../password-cracking/).
- **PandwaRF:** https://pandwarf.com
- **ChipWhisperer** is made by NewAE: https://www.newae.com — the entry-level
  ChipWhisperer-Nano/Lite are affordable ways into side-channel research.
- For deeper RF work beyond replay, step up to a full
  [SDR](sdr-radio.md).
