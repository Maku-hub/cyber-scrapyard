# Wifiphisher

> A rogue-access-point framework for red teams: it automates the evil-twin +
> captive-portal dance to phish Wi-Fi passwords or serve payloads — no handshake
> cracking required, just a convincing web page.

- **Link:** https://github.com/wifiphisher/wifiphisher
- **Type:** open source
- **Platform:** Linux

## Description

Wifiphisher automates social-engineering attacks over Wi-Fi. It stands up a fake
access point, uses deauthentication (or Known Beacons / KARMA) to steer victims
onto it, then serves a templated phishing page through a captive portal —
commonly a fake "router firmware upgrade" or "enter your Wi-Fi password to
reconnect" screen. The goal isn't to crack the WPA key but to get the user to
*hand it over*, or to deliver a malicious "update" binary. It ships with several
phishing scenarios and a template engine so you can tailor the pretext to the
engagement. This is squarely a **social-engineering / authorized red-team** tool:
it targets people, so scope and written permission are non-negotiable.

## Installation

```bash
# From source (recommended for the latest scenarios)
git clone https://github.com/wifiphisher/wifiphisher.git
cd wifiphisher && sudo python setup.py install

# Or on Kali
sudo apt install wifiphisher
```

## Usage examples

```bash
# Fully interactive: pick target AP and phishing scenario from the TUI
sudo wifiphisher

# Evil twin + the "firmware upgrade" page, auto-selecting interfaces
sudo wifiphisher -e "Target-SSID" -p firmware-upgrade

# Use Known Beacons instead of deauth to lure clients (stealthier)
sudo wifiphisher --known-beacons

# Specify the interfaces: one for the rogue AP, one for deauth/jamming
sudo wifiphisher -aI wlan0 -jI wlan1
```

## Notes & references

- Needs a wireless adapter (often two) that supports **AP mode** and packet
  injection; two cards let it run the rogue AP and the deauth simultaneously.
- Built-in scenarios include `firmware-upgrade`, `oauth-login`, and
  `plugin_update`; custom pretexts go in the phishing-page templates.
- Related, lower-level rogue-AP concepts (Karma/MANA, eaphammer for
  WPA-Enterprise) are covered in [Evil twin attacks](evil-twin-attacks.md);
  [Fluxion](fluxion.md) takes a similar captive-portal approach but *validates*
  the entered password against a captured handshake.
- Captured credentials are just the start — pivot with the rest of the
  [Wi-Fi toolkit](../wifi-wireless/) and document everything for the report.
