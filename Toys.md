### Note About Cost & DIY Alternatives

Many of the tools listed here may look expensive, and in reality **a large number of them can be recreated much more cheaply** using open-source hardware, microcontrollers, or DIY components.  
For example:
* A **Rubber Ducky** can be built using a simple **ATmega32U4 board (e.g., CJMCU / Pro Micro)** with custom HID-injection firmware [like this](./BadUSB/badusb.ino).
* A **WiFi pentesting adapter** can sometimes be replaced with a cheap card using the same chipset.
* Even tools like **Bash Bunny** **or O.MG Cable** have partial DIY equivalents using ESP8266/ESP32 boards and open-source payload frameworks.

So yes — **you can build simplified versions of these tools at a fraction of the cost**, and for learning or experimentation this is often completely fine.

Why are the official commercial tools expensive?

Even though many of these devices have cheap DIY alternatives, the official versions cost more because they offer:
* **Higher reliability** – they work consistently and are built to last.
* **Better firmware and features** – optimized payload engines, stable updates, and polished software.
* **Ease of use** – no setup, coding, or hardware tweaking; they work out of the box.
* **Support & updates** – regular improvements, bug fixes, documentation, and community resources.
* **Professional trust** – widely used in the industry, so results are predictable and standardized.

In short: **you pay for stability, convenience, and professional-grade quality**, not just the raw hardware.

## Authentication & Hardware Security Keys

* **YubiKey / Security Key NFC (Yubico)** – Best-in-class hardware keys for MFA, passwordless login, SSH, FIDO2.

## Wireless Tools

* **Alfa AWUS036ACHM / AWUS1900 / AWUS036AXML** – Strong, well-supported adapters for monitor mode & packet injection.
* **WiFi Pineapple** – Specialized device for Wi-Fi attacks, rogue AP, man-in-the-middle, training.

## USB Tools

* **Bash Bunny** – Multi-payload USB attack platform (keyboard injection, network spoofing, credential theft, etc.)
* **Rubber Ducky** – Classic “USB keyboard” attack device; extremely simple and effective.
* **O.MG Cable** – Weaponized cable capable of payload delivery, remote triggers, HID attacks.
* **USBKill V4** – Physical security tool that fries USB power lines (not for offensive use).

## Network Implants & Improv Devices

* **Packet Squirrel** – Inline network implant for packet capture & remote access.
* **Plunder Bug** – Compact network tap/sniffer.
* **Shark Jack** – Quick payload-based network reconnaissance tool.
* **Screen Crab** – Video capture implant (screenshots over network).

## Radio, SDR & Wireless Research

* **RTL-SDR V4** – Budget software-defined radio; great for learning SDR basics.
* **HackRF One** – Mid-range SDR with TX/RX; ideal for wireless hacking research.
* **KrakenSDR** – Multi-channel SDR for advanced RF analysis, direction finding, advanced research.

## RFID, NFC & Access Control

* **Proxmark 3 RDV4.01** – The best tool for RFID research, cloning, cracking, and analysis.
* **Chameleon Ultra** – Powerful NFC emulator/cloner for testing & research.
* **Ultimate Magic Card (Gen4)** – HF card emulator with advanced features.
* **RFID Field Detector** – Simple tool for visualization of RFID field presence.

## Multi-Tool & Misc Hardware

* **Flipper Zero** – Multi-protocol cyber toy: sub-GHz, RFID, NFC, IR, GPIO; huge ecosystem.
* **PandwaRF** – Sub-GHz hacking tool for RF replay and analysis.
* **ChipWhisperer** – Hardware hacking & side-channel analysis platform.

## Software Tools

* **Burp Suite Professional (PortSwigger Pro)** – Industry-standard web application pentest suite.
* **Binary Ninja** – Advanced reverse engineering platform (clean UI, powerful scripting).
* **Shodan** – “Search engine for the internet”; great for recon, mapping exposed systems.
