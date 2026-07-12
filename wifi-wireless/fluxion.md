# Fluxion

> An evil-twin attack that skips the wordlist: it captures the WPA handshake, then
> tricks a user into typing the real Wi-Fi password into a captive portal — and
> verifies it against the handshake so you know it's correct.

- **Link:** https://github.com/FluxionNetwork/fluxion
- **Type:** open source
- **Platform:** Linux

## Description

Fluxion combines an evil-twin rogue AP with a captive-portal phishing page, but
its clever twist is **verification**. First it captures a WPA/WPA2 4-way
handshake from the target network (or PMKID). Then it clones the network as an
open AP, deauthenticates clients off the real one, and presents anyone who
reconnects with a login page asking for the Wi-Fi password. Because it already
has the handshake, it can check each submitted password against it in real time —
so it only stops (and hands you the key) once the *correct* passphrase is entered.
That sidesteps offline cracking entirely when the passphrase is strong but the
user is willing to type it. It's a menu-driven wrapper around aircrack-ng,
hostapd, dnsmasq, and friends — and, being a social-engineering attack, strictly
for **authorized** engagements.

## Installation

```bash
# Clone and run; Fluxion installs its own dependencies on first launch
git clone https://github.com/FluxionNetwork/fluxion.git
cd fluxion && sudo ./fluxion.sh
```

## Typical workflow

1. **Launch** — `sudo ./fluxion.sh` and choose your language/interface; the menu
   drives the whole attack.
2. **Scan & select target** — Fluxion runs an airodump-style scan; pick the
   target AP (note it needs connected clients to force a handshake).
3. **Capture a handshake** — choose the "Handshake Snooper" attack; it deauths
   clients and grabs the 4-way handshake, which it uses later as the password
   oracle.
4. **Start the captive portal** — choose the "Captive Portal" attack: Fluxion
   spins up the twin AP, a fake DNS/DHCP, and a language-matched login page.
5. **Collect the key** — when a user submits the correct passphrase (validated
   against the captured handshake), Fluxion stops and reports it.

## Notes & references

- Handshake capture is a prerequisite for the portal's password check — it's the
  same 4-way handshake you'd feed to [Aircrack-ng](aircrack-ng.md) or
  [hashcat](../password-cracking/hashcat.md), just used as a live oracle instead.
- Compared with [Wifiphisher](wifiphisher.md): Wifiphisher will accept *any*
  entered text, while Fluxion only accepts the verified-correct password —
  fewer false results, at the cost of needing a handshake first.
- Deauthentication and monitor mode come from [Aircrack-ng](aircrack-ng.md);
  broader rogue-AP theory is in [Evil twin attacks](evil-twin-attacks.md).
- Defences are the same as for any evil twin: WPA3/OWE, 802.1X with
  server-cert validation, and rogue-AP monitoring via [Kismet](kismet.md).
