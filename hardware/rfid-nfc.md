# RFID & NFC Tools

> Devices for reading, cloning, emulating, and cracking contactless cards and
> tags — the toolkit for access-control and badge security research (both
> low-frequency 125 kHz and high-frequency 13.56 MHz).

- **Link:** https://proxmark.com
- **Type:** open hardware + commercial builds
- **Platform:** cross-platform client (Linux/Windows/macOS)

## Description

RFID/NFC underpins door badges, transit cards, hotel keys, and payment tokens.
Research tools let you sniff card–reader exchanges, read UIDs and sectors, crack
weak keys (e.g. MIFARE Classic's broken Crypto-1), clone credentials, and
emulate a card to test a reader. Cards split into **LF (125 kHz)** — often
trivially cloneable EM4100/HID Prox — and **HF (13.56 MHz)** — MIFARE, NTAG,
DESFire, with a wide range of security. So-called **"magic" cards** are special
blank tags whose normally read-only UID block is writable, which is what makes
cloning a target card onto them possible.

## Devices worth knowing

| Device | Role |
| --- | --- |
| **Proxmark3 RDV4** | The premier RFID/NFC research tool — read, sniff, crack, clone, emulate (LF + HF) |
| **Chameleon Ultra** | Powerful pocket NFC emulator/cloner; stores and replays multiple card profiles |
| **Ultimate Magic Card (Gen4)** | Advanced writable HF card that emulates various MIFARE types |
| **RFID Field Detector** | Simple tool that lights up to visualize the presence/strength of an RFID field |

## Usage examples

```text
# Proxmark3 client — detect what's on the antenna
[usb] pm3 --> hf search      # identify a high-frequency (13.56 MHz) tag
[usb] pm3 --> lf search      # identify a low-frequency (125 kHz) tag

# Crack MIFARE Classic keys, then dump the card
[usb] pm3 --> hf mf autopwn

# Clone an EM4100 LF tag onto a writable T5577 card
[usb] pm3 --> lf em 410x clone --id 1234567890
```

## Notes & references

- The open-source Proxmark3 firmware/client is maintained by the RFID Research
  Group: https://github.com/RfidResearchGroup/proxmark3 — the RDV4 is the
  recommended hardware revision.
- **Chameleon Ultra** is open hardware/firmware:
  https://github.com/RfidResearchGroup/ChameleonUltra
- MIFARE Classic's Crypto-1 cipher is broken; DESFire EV1/EV2/EV3 and modern
  NTAG variants are the secure successors — don't assume a "contactless" badge
  is safe.
- [Flipper Zero](multitools.md) reads/emulates many common LF and HF tags too,
  though the Proxmark3 goes far deeper for cracking and analysis.
