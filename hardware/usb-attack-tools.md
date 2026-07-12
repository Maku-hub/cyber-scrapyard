# USB Attack Tools

> Malicious-by-design USB devices: keystroke ("HID") injectors, multi-payload
> attack platforms, weaponized cables, and physical "USB killers." They exploit
> the trust a computer places in anything plugged into its ports.

- **Link:** https://hak5.org
- **Type:** commercial (hardware)
- **Platform:** target-agnostic (attacks Windows/Linux/macOS hosts)

## Description

A computer implicitly trusts a USB keyboard, so a device that *pretends* to be
one can type commands faster than any human — this is **HID (Human Interface
Device) injection**, or "BadUSB." From there the category scales up: platforms
that emulate storage, network adapters, and serial alongside HID; ordinary-
looking cables with a hidden implant and Wi-Fi for remote triggering; and, at
the destructive end, devices that don't hack the host at all but physically
fry it.

## Devices worth knowing

| Device | What it does |
| --- | --- |
| **USB Rubber Ducky** | The classic HID injector — poses as a USB keyboard and runs a scripted payload (DuckyScript) |
| **Bash Bunny** | Multi-payload attack platform: HID injection, network (Ethernet) spoofing, credential theft, exfil |
| **O.MG Cable** | A weaponized cable that looks normal but hides an implant for payload delivery, keylogging, and remote HID over Wi-Fi |
| **USBKill V4** | Physical destruction device — charges and discharges high voltage into the USB data lines, permanently damaging hardware |

## Usage examples

```text
# DuckyScript: open a Run dialog on Windows and launch PowerShell (illustrative)
DELAY 1000
GUI r
DELAY 500
STRING powershell
ENTER
```

## Notes & references

- **Rubber Ducky, Bash Bunny, O.MG Cable** and most of this class are from
  **Hak5**: https://hak5.org — the O.MG line is by Mischief Gadgets
  (https://o.mg.lol).
- **USBKill:** https://usbkill.com — this is a *destructive physical attack*
  that irreversibly damages equipment. Treat it accordingly.
- Defenses: disable USB HID auto-enroll / use USB port control (device
  allow-lists), lock the screen when away, and deploy USB data blockers for
  charging from untrusted ports.
- **BadUSB DIY:** a from-scratch ATmega32U4 keystroke injector is *coming soon*
  as a **separate repo/project** — see [DIY & cheaper equivalents](diy-alternatives.md).
