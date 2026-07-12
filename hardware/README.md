# Hardware & Physical Tools

Physical gadgets for security work: radios, RFID/NFC tools, Wi-Fi adapters,
USB attack platforms, network implants, and multitools. This is the gear you
reach for when the target isn't (only) on the network — badges, wireless
signals, exposed ports, and physical access.

> ⚠️ **Authorized use only.** Much of this hardware is designed to intercept,
> emulate, inject, or destroy. Only use it against systems, cards, signals, and
> premises you own or have explicit written permission to test. Owning some of
> this equipment is regulated in certain jurisdictions — check your local law.

## Pages

| Page | Summary |
| --- | --- |
| [Security keys](security-keys.md) | YubiKey / FIDO2 hardware authenticators for MFA and passwordless login |
| [Wi-Fi adapters](wifi-adapters.md) | Alfa cards for monitor mode & packet injection — which chipsets and why |
| [SDR & radio](sdr-radio.md) | RTL-SDR, HackRF One, KrakenSDR — software-defined radio |
| [RFID & NFC](rfid-nfc.md) | Proxmark3, Chameleon Ultra, magic cards — access-control research |
| [Bluetooth & BLE](bluetooth-ble.md) | Ubertooth One, nRF/Sniffle sniffers — capturing and testing Bluetooth/BLE |
| [Hardware hacking tools](hardware-hacking-tools.md) | Bus Pirate, JTAGulator, logic analyzers/sigrok — UART/JTAG/SPI work |
| [USB attack tools](usb-attack-tools.md) | Rubber Ducky, Bash Bunny, O.MG Cable, USBKill — HID injection & more |
| [Network implants](network-implants.md) | Packet Squirrel, Shark Jack, Plunder Bug, Screen Crab |
| [Multitools](multitools.md) | Flipper Zero, Pwnagotchi, PandwaRF, ChipWhisperer |
| [DIY & cheaper equivalents](diy-alternatives.md) | Rebuild much of the above for a fraction of the price |

## Cost & DIY: the short version

A lot of this gear looks expensive, and **a good share of it can be rebuilt far
more cheaply** with open hardware, microcontrollers, or off-the-shelf parts. A
Rubber Ducky is essentially an ATmega32U4 board with HID-injection firmware; a
pentest Wi-Fi card can often be swapped for a cheap dongle on the *same
chipset*; even a Bash Bunny or O.MG Cable has partial ESP8266/ESP32-based
equivalents. For learning and experimentation, the simplified versions are
usually more than enough. See [DIY & cheaper equivalents](diy-alternatives.md).

So why do the official, commercial versions cost more? You pay for reliability,
polished firmware and payload engines, out-of-the-box ease of use, ongoing
support and updates, and professional trust (predictable, repeatable results).
In short: **you're paying for stability, convenience, and professional-grade
quality**, not just the raw hardware. Full discussion in
[DIY & cheaper equivalents](diy-alternatives.md).

## See also

- [Wi-Fi & Wireless](../wifi-wireless/) — the software side of wireless attacks
  (Aircrack-ng, evil twin, WPA) that pairs with these adapters and radios.
- [Developer Tools & Productivity](../dev-tools/) — Arduino IDE and the tooling
  you'll use to flash and program DIY builds.
