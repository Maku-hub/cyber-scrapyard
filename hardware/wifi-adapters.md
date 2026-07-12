# Wi-Fi Adapters (Monitor Mode & Injection)

> External USB Wi-Fi cards with chipsets that support **monitor mode** and
> **packet injection** — the prerequisite for almost every wireless attack and
> capture workflow.

- **Link:** https://www.alfa.com.tw
- **Type:** commercial (hardware)
- **Platform:** best support on Linux/Kali (drivers vary on Windows/macOS)

## Description

Most built-in laptop Wi-Fi chips can only associate with a network like a normal
client. For security work you need a card that can enter **monitor mode**
(passively capture all nearby 802.11 frames) and perform **packet injection**
(craft and transmit frames — deauth, evil twin, handshake forcing). The chipset
is what matters, not the brand: pick one with mature Linux drivers that support
both features, plus **virtual interfaces** if you want to run an evil-twin or
"known beacons" attack (broadcasting many fake SSIDs) while still capturing.

**Alfa Network** cards are the community default because their chipsets are
well-documented and well-supported in Kali. Note that many attacks want *high
transmit power* — an evil twin only works if clients hear your rogue AP louder
than the real one.

## Recommended models & chipsets

| Model | Chipset | Bands | Notes |
| --- | --- | --- | --- |
| Alfa AWUS036ACHM | MediaTek MT7610U | 2.4 + 5 GHz | Compact, low power draw, solid monitor/injection |
| Alfa AWUS036ACH / AWUS1900 | Realtek RTL8812AU/8814AU | 2.4 + 5 GHz | High power, needs the out-of-tree `rtl88xxau` driver |
| Alfa AWUS036AXML | MediaTek MT7921AU | 2.4 + 5 + 6 GHz (Wi-Fi 6E) | Newer 802.11ax card; kernel/driver support still maturing |
| Alfa AWUS036NHA | Atheros AR9271 | 2.4 GHz only | The classic "just works" card; in-kernel `ath9k_htc` driver |

## Usage examples

```bash
# Identify the interface and put it into monitor mode
sudo airmon-ng start wlan0

# Confirm the mode change (interface often becomes wlan0mon)
iw dev

# Capture nearby networks and clients
sudo airodump-ng wlan0mon
```

## Notes & references

- Realtek RTL88xxAU cards give great range but usually need a DKMS driver such
  as [aircrack-ng/rtl8812au](https://github.com/aircrack-ng/rtl8812au).
- For evil-twin / known-beacons attacks the chipset must support creating
  **virtual interfaces** (e.g. the older Alfa AWUS036CH is a known-good example).
- The purpose-built **Wi-Fi Pineapple** (Hak5) bundles rogue-AP / MITM tooling
  into a dedicated device if you don't want to script it yourself.
- The attacks themselves live in [Wi-Fi & Wireless](../wifi-wireless/)
  (Aircrack-ng, Wifite, evil twin, WPA handshakes).
- The [Wi-Fi Assessment](../scenarios/wifi-assessment.md) scenario walks the
  end-to-end workflow, starting from choosing the right adapter.
