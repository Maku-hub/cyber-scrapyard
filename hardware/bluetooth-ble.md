# Bluetooth & BLE Tools

> Hardware and tooling for sniffing, analyzing, and testing Bluetooth Classic
> and Bluetooth Low Energy (BLE) — the wireless layer behind wearables, locks,
> medical devices, and a huge slice of IoT.

- **Link:** https://github.com/greatscottgadgets/ubertooth
- **Type:** open hardware / open source
- **Platform:** cross-platform (Linux best supported; Kismet, Wireshark, `nRF Connect`)

## Description

Bluetooth and especially BLE are everywhere, and much of it ships with weak or
absent pairing security. Capturing this traffic needs radios that can follow
BLE's fast frequency hopping — ordinary Bluetooth dongles can talk to devices
but can't passively sniff them. Dedicated sniffers like the Ubertooth One let
you watch advertising and connection packets over the air, while cheap Nordic
dev boards flashed with sniffer firmware cover single-connection BLE capture on
a budget. It's the entry point for IoT and wireless security research on
anything that pairs over Bluetooth.

## Devices worth knowing

| Device | What it does | Role |
| --- | --- | --- |
| **Ubertooth One** | Open-source 2.4 GHz wireless dev platform for Bluetooth experimentation and BLE sniffing | The reference open-source Bluetooth sniffer |
| **Nordic nRF52840 dongle** | Cheap dev board flashed with **nRF Sniffer for BLE** firmware; captures a single BLE connection into Wireshark | Budget BLE capture for learning |
| **Sniffle + TI CC1352/CC26x2** | Open-source BLE5 sniffer firmware on TI LaunchPad boards; robust connection following | Modern BLE (incl. long-range/extended adv) |
| **Ubertooth + Kismet** | Ubertooth as a capture source inside the Kismet suite | Survey and log nearby Bluetooth activity |

## Usage examples

```bash
# Confirm the Ubertooth is detected and show firmware/serial info
ubertooth-util -v

# Passively scan for Bluetooth Classic devices in range
ubertooth-scan

# Follow BLE advertising/connection traffic and pipe it to Wireshark via a pipe
ubertooth-btle -f -c /tmp/pipe

# Dump BLE packets straight to a PCAP for offline analysis
ubertooth-btle -f -q capture.pcap
```

## Notes & references

- **Ubertooth One** is made by Great Scott Gadgets — build/install the host
  tools from source or your distro's package:
  https://github.com/greatscottgadgets/ubertooth
- **Nordic nRF Sniffer for BLE** turns a ~$10 nRF52840 dongle into a
  Wireshark capture source:
  https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE
- **Sniffle** (NCC Group) is an excellent open-source sniffer for BLE 5 on TI
  hardware: https://github.com/nccgroup/Sniffle
- For interacting with (not just sniffing) BLE devices, the phone apps
  **nRF Connect** and **LightBlue** enumerate services/characteristics and let
  you read/write GATT attributes.
- The [Flipper Zero](multitools.md) can scan and interact with some BLE devices
  but is not a passive sniffer.
- ⚠️ Sniffing and injecting Bluetooth traffic is legally restricted — only test
  devices and connections you own or are authorized to assess.
