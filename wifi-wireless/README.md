# Wi-Fi & Wireless

Tools and techniques for auditing 802.11 networks: putting an adapter into
monitor mode, capturing WPA/WPA2 material, attacking WPS and legacy WEP, and
impersonating networks with rogue access points. Most of this needs a wireless
adapter that supports **monitor mode** and **packet injection** (and, for
evil-twin work, **virtual interfaces**) — the Alfa AWUS036CH is a common choice.

> ⚠️ **Authorized use only.** Wireless attacks affect real radios, networks, and
> people around you. Only test networks you own or are explicitly permitted to
> assess.

## Tools

| Tool | Summary |
| --- | --- |
| [Aircrack-ng](aircrack-ng.md) | The core suite: monitor mode, handshake capture, deauth injection, and offline cracking |
| [Wifite](wifite.md) | Automates the common WPA/WPS/WEP attacks by driving Aircrack-ng, Reaver, and others |
| [Kismet](kismet.md) | Passive detector/sniffer/IDS — maps networks and clients (incl. hidden ones) without transmitting |
| [WPS attacks](wps-attacks.md) | Reaver + Bully: brute-force the WPS PIN to recover the passphrase regardless of its strength |
| [Pixiewps](pixiewps.md) | Offline WPS "Pixie Dust" cracker — recovers the PIN in seconds from one handshake |
| [Evil twin attacks](evil-twin-attacks.md) | Rogue-AP concepts — evil twin, Karma/MANA, known beacons — with airgeddon and eaphammer |
| [Wifiphisher](wifiphisher.md) | Rogue-AP phishing framework — captive-portal pages to harvest Wi-Fi passwords / payloads |
| [Fluxion](fluxion.md) | Evil-twin + captive portal that validates the entered password against a captured handshake |
| [hcxtools](hcxtools.md) | hcxdumptool + hcxpcapngtool: clientless PMKID capture, converted for hashcat |
| [Wi-Fi security overview](wifi-security-overview.md) | Reference: state of WEP/WPA/WPA2/WPA3 and PSK vs Enterprise vs WPS |

## Typical WPA2-PSK workflow

1. **Enable monitor mode** — `airmon-ng check kill && airmon-ng start wlan0`.
2. **Find the target** — `airodump-ng wlan0mon`; note BSSID, channel, clients.
3. **Capture** — lock onto the AP with `airodump-ng -w cap --bssid <B> -c <CH>`,
   or grab a **PMKID** with [hcxdumptool](hcxtools.md) (no clients needed).
4. **Speed it up** — deauth a client (`aireplay-ng --deauth`) to force a
   handshake.
5. **Crack offline** — [aircrack-ng](aircrack-ng.md) for quick jobs, or convert
   and run [hashcat](../password-cracking/hashcat.md) `-m 22000` for real speed.

> Rule of thumb: **check for WPS first** (a locked-off passphrase can still fall
> via the PIN), **try a clientless PMKID** before deauthing, and remember a
> captured handshake is only as crackable as your
> [wordlist](../password-cracking/wordlists.md).

For the whole workflow end to end — hardware selection through reporting — follow
the [Wi-Fi Assessment](../scenarios/wifi-assessment.md) scenario.

See also: [Password Cracking & Hashing](../password-cracking/) for cracking
captured handshakes/hashes, [Network Traffic Analysis](../network-analysis/) for
inspecting captured traffic, and [Hardware & Physical Tools](../hardware/) for
adapters and RF gear.
