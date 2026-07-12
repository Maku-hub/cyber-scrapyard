# Wifite

> An automated wireless auditor that wraps the Aircrack-ng suite, Reaver, and
> friends — point it at the airwaves and it runs the common attacks for you.

- **Link:** https://github.com/derv82/wifite2
- **Type:** open source
- **Platform:** Linux

## Description

Wifite automates the tedious parts of Wi-Fi auditing. Instead of running
`airmon-ng`, `airodump-ng`, and `aireplay-ng` by hand, you launch Wifite and it
enumerates nearby networks, deauthenticates clients, captures WPA handshakes and
PMKIDs, and attacks WPS and WEP where present — then hands captured hashes off
for cracking. It's the fastest way to sweep an environment; reach for
[Aircrack-ng](aircrack-ng.md) directly when you need fine control over a single
target.

## Installation

```bash
# Pre-installed on Kali; otherwise:
sudo apt install wifite

# Or from source
git clone https://github.com/derv82/wifite2.git
cd wifite2 && sudo python3 setup.py install
```

## Usage examples

```bash
# Scan and interactively pick targets (Ctrl-C to stop scanning and choose)
sudo wifite

# Only target WPA/WPA2 networks and require a decent signal
sudo wifite --wpa --pow 50

# Only go after WPS-enabled access points
sudo wifite --wps

# Attack a single network by ESSID
sudo wifite --essid "HomeWiFi"

# Crack captured handshakes offline against a wordlist
sudo wifite --dict /usr/share/wordlists/rockyou.txt
```

## Notes & references

- Wifite drives other tools under the hood — install `aircrack-ng`, `reaver`,
  `bully`, `tshark`, and `hashcat` to unlock all attack types.
- Captured handshakes land in `hs/` and can be cracked later with
  [hashcat](../password-cracking/hashcat.md) or
  [aircrack-ng](aircrack-ng.md).
- Requires an adapter that supports monitor mode and injection; Wifite enables
  monitor mode automatically.
- Kali tool page: https://www.kali.org/tools/wifite/
- For the manual equivalents, see [WPS attacks](wps-attacks.md) and
  [hcxtools](hcxtools.md).
