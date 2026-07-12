# FTK Imager

> A free, widely trusted tool for creating forensic disk and memory images,
> previewing evidence, and exporting files — the standard first step for
> acquiring evidence in a forensically sound way.

- **Link:** https://www.exterro.com/digital-forensics-software/ftk-imager
- **Type:** freeware (from Exterro, formerly AccessData)
- **Platform:** Windows (a Linux/CLI imager variant has existed)

## Description

FTK Imager makes bit-for-bit copies of drives and volatile memory while
preserving integrity — it computes MD5/SHA-1 hashes during acquisition so you can
prove the image matches the source. It writes standard formats (raw `dd`, E01/
EnCase, AFF), can capture live RAM, and lets you mount and browse an image
read-only to preview and export individual files (including some deleted ones)
without altering the evidence. It's free and courtroom-familiar, which is why
it's the default acquisition tool for many responders.

## Installation

Download the installer from Exterro (registration required) and run it on the
analysis workstation (or from a write-blocked USB for live acquisition):
https://www.exterro.com/digital-forensics-software/ftk-imager

## Typical workflow

1. **Capture memory (if the box is live)** — `File → Capture Memory`, choose a
   destination on external/removable media, and save the RAM image for
   [Volatility](volatility.md).
2. **Image a disk** — `File → Create Disk Image`, pick the source (physical
   drive / logical volume), choose a format (**E01** with compression is common),
   fill in case metadata, and let it hash-verify on completion.
3. **Use a write blocker** — always acquire source disks through a hardware/
   software write blocker so you never modify the original.
4. **Preview & export** — `File → Add Evidence Item` to mount an image read-only;
   browse the filesystem, view files, and export specific artifacts or the
   registry hives for parsing.
5. **Record hashes** — note the acquisition MD5/SHA-1 for the chain of custody.

## Notes & references

- Always image to a destination **different** from the source, on media large
  enough for the full drive.
- E01 (EnCase Evidence Format) stores metadata and hashes inside the image and
  supports compression; raw `dd` is universal but larger and metadata-less.
- Alternative/companion imagers: `dd`/`dc3dd` (Linux), Guymager, WinPmem/DumpIt
  (memory-only), and [KAPE](kape.md) for targeted artifact collection instead of
  full images.
- Feed images into [Autopsy](autopsy-sleuthkit.md) (disk) and
  [Volatility](volatility.md) (memory).
