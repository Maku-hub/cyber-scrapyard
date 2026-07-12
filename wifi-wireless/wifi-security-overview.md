# Wi-Fi Security Overview (WEP / WPA / WPA2 / WPA3)

> A quick map of the Wi-Fi encryption standards, how each one fails, and which
> tools in this category attack which mode.

- **Link:** https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access
- **Type:** reference
- **Platform:** n/a

## Description

Before choosing an attack you need to know what you're up against. Wi-Fi
security has evolved through four generations; older ones are broken outright,
newer ones only fall to specific misconfigurations. This page summarises the
state of each and points to the relevant tools.

## The standards, oldest to newest

- **WEP** — **broken.** Weak RC4 IVs leak the key; capture enough traffic
  (accelerate it with an ARP-replay attack) and the key falls in minutes. Only
  seen on legacy gear. Attack with [Aircrack-ng](aircrack-ng.md).
- **WPA (TKIP)** — **insecure.** A stopgap upgrade over WEP; deprecated and
  vulnerable. Treat any WPA/TKIP network as crackable.
- **WPA2** — **still standard, but attackable.** Uses AES-CCMP. Its two common
  modes fail differently:
  - **WPA2-PSK (Personal)** — everyone shares one passphrase. Capture the 4-way
    handshake (or a PMKID) and brute-force it offline. The passphrase is the
    only secret, so strong passwords are the whole defence. Tools:
    [Aircrack-ng](aircrack-ng.md), [hcxtools](hcxtools.md),
    [hashcat](../password-cracking/hashcat.md).
  - **WPA2-Enterprise (MGT / 802.1X)** — authentication is delegated to a
    RADIUS server, so there's no shared key to capture. Harder to attack; the
    practical path is a rogue AP that captures EAP (e.g. MSCHAPv2) credentials.
    See [evil twin attacks](evil-twin-attacks.md).
- **WPA3** — **current best practice.** Replaces the PSK handshake with SAE
  (Dragonfly), which resists offline dictionary attacks, and adds forward
  secrecy and OWE for open networks. Not immune — see the Dragonblood research
  at https://wpa3.mathyvanhoef.com/ — but no easy offline cracking of a strong
  passphrase.

## WPS — a side door regardless of the standard

**WPS** (Wi-Fi Protected Setup) is an easy-join feature bolted onto WPA/WPA2. Its
8-digit PIN is brute-forceable in hours **no matter how strong the Wi-Fi
passphrase is**, after which the router simply reveals the key. Always check for
it and disable it. See [WPS attacks](wps-attacks.md).

## Notes & references

- Practical takeaways: use **WPA3** (or WPA2-AES with a long random passphrase),
  **disable WPS**, and prefer **Enterprise/802.1X** where you can run a RADIUS
  server.
- PSK strength is everything for WPA2-Personal — a captured handshake is only as
  crackable as the [wordlist](../password-cracking/wordlists.md) you throw at it.
- Related pages: [Aircrack-ng](aircrack-ng.md), [hcxtools](hcxtools.md),
  [WPS attacks](wps-attacks.md), [evil twin attacks](evil-twin-attacks.md).
