# Evil Twin & Rogue AP Attacks

> Instead of cracking a network, you impersonate one: stand up a fake access
> point that looks identical to a trusted network and let clients connect to
> you. Covers evil twin, Karma/MANA, and known-beacon attacks with airgeddon and
> eaphammer.

- **Link:** airgeddon https://github.com/v1s1t0r1sh3r3/airgeddon · eaphammer https://github.com/s0lst1c3/eaphammer
- **Type:** open source
- **Platform:** Linux

## Description

Rogue-AP attacks exploit how clients trust and auto-reconnect to networks. They
are powerful for phishing captive portals, harvesting credentials, and
man-in-the-middle positioning — and they demand explicit authorization because
they affect real client devices.

- **Evil twin** — deauthenticate clients off the legitimate AP, then broadcast
  an identical SSID (often with a stronger signal) hoping victims reconnect to
  you. Frequently paired with a fake captive portal that asks for the Wi-Fi
  password. Your adapter needs enough transmit power to out-shout the real AP.
- **Karma / MANA** — when a device with auto-connect enabled isn't associated,
  it constantly sends *probe requests* asking "is network X here?". A Karma/MANA
  rogue AP answers "yes" to whatever the client asks for, impersonating any
  network in the device's saved list. MANA improves on Karma by also serving
  common SSIDs to devices that only broadcast-probe.
- **Known beacons** — broadcast a large list of popular SSID names so devices
  that have any of them saved will auto-join.

Against WPA-Enterprise (802.1X/MGT) networks, a rogue AP with `eaphammer` can
capture MSCHAPv2 challenge/response hashes for offline cracking. An adapter that
supports **virtual interfaces** (e.g. Alfa AWUS036CH) makes running the fake AP
and the deauth from one card much easier.

## Installation

```bash
# airgeddon — menu-driven wireless attack framework
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
cd airgeddon && sudo bash airgeddon.sh

# eaphammer — evil twin against WPA-Enterprise / captive portals
git clone https://github.com/s0lst1c3/eaphammer.git
cd eaphammer && sudo ./kali-setup
```

## Usage examples

### airgeddon — guided evil twin

```bash
# Launch the interactive menu, then choose:
#   Evil Twin attacks menu -> deauth + fake AP (optionally with captive portal)
sudo bash airgeddon.sh
```

### eaphammer — rogue AP & credential capture

```bash
# Generate the certificate eaphammer uses for its rogue AP (one-time)
sudo ./eaphammer --cert-wizard

# Stand up a rogue AP that captures WPA-Enterprise (EAP) credentials
sudo ./eaphammer -i wlan0 --channel 1 --auth wpa-eap --essid "CorpWiFi" --creds

# Karma/known-beacons style: respond to client probe requests
sudo ./eaphammer -i wlan0 --essid "CorpWiFi" --captive-portal --known-beacons
```

## Notes & references

- **Authorization matters.** These attacks hit client devices and users, not
  just infrastructure — get it in writing and scope it tightly.
- Defences: disable auto-connect to open networks, prefer WPA3/OWE and 802.1X
  with server-certificate validation, and monitor for rogue APs with
  [Kismet](kismet.md).
- Deauthentication (used to push clients to the twin) is done with
  [Aircrack-ng](aircrack-ng.md)'s `aireplay-ng`.
- Credential/hash captures feed offline cracking with
  [hashcat](../password-cracking/hashcat.md).
- Background on enterprise vs PSK vs WPS: [Wi-Fi security overview](wifi-security-overview.md).
