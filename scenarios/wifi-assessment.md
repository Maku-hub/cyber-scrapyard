# Wi-Fi Assessment

> You have a wireless network in scope. Test its encryption strength and how
> exposed its clients are — from choosing the right radio to (optionally)
> standing up a controlled evil twin.

## Scope & assumptions

- **Authorized use only.** Wireless testing spills easily onto neighbours, so
  pin down in writing which SSIDs/BSSIDs are in scope, the physical location, and
  whether client-side attacks (deauth, evil twin) are permitted. Never capture or
  crack networks you don't own or aren't contracted to test.
- You are on-site (or have a remote node) within RF range of the target AP.
- The flow moves from passive survey to active capture to offline cracking, with
  client-side attacks last and only if explicitly authorized.

## Phase 1 — Pick hardware & enable monitor mode

Everything downstream depends on a radio that supports monitor mode and packet
injection. Choose a known-good adapter before anything else.

- Select a supported chipset from [Wi-Fi adapters](../hardware/wifi-adapters.md),
  then review the [Wi-Fi security overview](../wifi-wireless/wifi-security-overview.md)
  to map which attacks apply to the target's encryption (WPA2 vs WPA3, PSK vs
  Enterprise).

```bash
airmon-ng start wlan0     # put the adapter into monitor mode (wlan0mon)
```

## Phase 2 — Survey the environment

Passively map the airspace: which APs and clients exist, channels, signal
strength, and encryption. This scopes the target and picks the right channel to
work on.

- Run [Kismet](../wifi-wireless/kismet.md) for a rich passive survey, or
  `airodump-ng` from [Aircrack-ng](../wifi-wireless/aircrack-ng.md) for a quick
  channel/client view.

```bash
airodump-ng wlan0mon                       # live survey of APs and clients
```

## Phase 3 — Capture a handshake or PMKID

To test a WPA/WPA2-PSK network you need material to crack offline: either a
4-way handshake (from a connecting client, optionally nudged with a deauth) or a
client-less PMKID straight from the AP.

- Capture the WPA handshake with [Aircrack-ng](../wifi-wireless/aircrack-ng.md)
  (`airodump-ng` to capture, `aireplay-ng` to deauth if in scope), or grab a
  PMKID with [hcxtools](../wifi-wireless/hcxtools.md).
- [Wifite](../wifi-wireless/wifite.md) automates this whole capture step across
  multiple targets if you prefer a guided workflow.

```bash
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon   # capture handshake
hcxdumptool -i wlan0mon -o pmkid.pcapng                       # attempt PMKID capture
```

## Phase 4 — Crack offline

Take the captured handshake/PMKID off the air and attempt to recover the
passphrase offline — this demonstrates real key strength without further RF
activity.

- Convert the capture with [hcxtools](../wifi-wireless/hcxtools.md) and crack it
  with [Hashcat](../password-cracking/hashcat.md) (mode 22000 for WPA), or use
  [Aircrack-ng](../wifi-wireless/aircrack-ng.md) for a quick dictionary attempt.

```bash
hcxpcapngtool -o hash.22000 pmkid.pcapng   # convert capture to hashcat format
hashcat -m 22000 hash.22000 wordlist.txt    # offline WPA crack
```

## Phase 5 — WPS check

WPS is a common shortcut past a strong passphrase. Test whether the AP exposes a
guessable or offline-crackable WPS PIN.

- Follow the [WPS attacks](../wifi-wireless/wps-attacks.md) page, and attempt an
  offline Pixie-Dust attack with [Pixiewps](../wifi-wireless/pixiewps.md) where
  the AP is vulnerable.

## Phase 6 — Evil twin for client-side exposure (optional, if authorized)

If client-side testing is in scope, a controlled rogue AP shows whether clients
will connect to an impostor and leak credentials — a realistic phishing/roaming
risk.

- Stand up a controlled rogue AP following
  [evil twin attacks](../wifi-wireless/evil-twin-attacks.md), keeping it tightly
  scoped so only sanctioned test clients are affected.

## Reporting / next steps

Report the encryption type and whether the passphrase was recovered (and how
long it took — a proxy for strength), any WPS weakness, and client behaviour
against the evil twin. Recommend concrete fixes: long random PSK or 802.1X/WPA3,
WPS disabled, PMF enabled, and client profiles that don't auto-join open/known
SSIDs. Securely destroy captured handshakes and any recovered secrets per the
rules of engagement.
