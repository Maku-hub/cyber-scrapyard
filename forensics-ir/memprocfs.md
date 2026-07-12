# MemProcFS

> Mounts a memory image (or live RAM) as a browsable filesystem: instead of
> running plugins, you `cd` into processes, handles, and registry hives and read
> them like files.

- **Link:** https://github.com/ufrisk/MemProcFS
- **Type:** open source
- **Platform:** Windows, Linux

## Description

MemProcFS turns memory forensics inside out. Rather than issuing plugin commands
against a dump, it parses the image once and exposes everything as a virtual
filesystem — a folder per process containing its modules, handles, memory
regions, tokens, and network connections, plus system-wide views of the registry,
services, and more. You explore it with a file manager or ordinary shell tools,
which makes triage fast and intuitive. It reads raw dumps, hibernation files, and
crash dumps, can attach to live memory via drivers (PCILeech/DumpIt), and ships a
Python/C API and a YARA-scanning "forensic" mode for automated analysis.

## Installation

```bash
# Download the prebuilt release for Windows or Linux
# from https://github.com/ufrisk/MemProcFS/releases and unzip it
# (Windows also needs the Dokany driver for the mount to appear as a drive)
```

## Usage examples

```bash
# Mount a raw memory image at M: (Windows) or a mount point (Linux)
MemProcFS.exe -device memdump.raw -mount M:

# Linux equivalent
./memprocfs -device memdump.raw -mount /mnt/mem

# Run in "forensic" mode: build timelines, run YARA, populate the /forensic dir
MemProcFS.exe -device memdump.raw -mount M: -forensic 1

# Then just browse — e.g. list processes, read a process's handles/modules:
#   M:\name\            (one folder per process)
#   M:\name\explorer.exe-1234\handles\
#   M:\forensic\timeline\   (generated timelines, CSV)
#   M:\registry\           (mounted hives)
```

## Notes & references

- The **`/forensic`** directory is the power feature: auto-generated timelines,
  NTFS MFT recovery, and findings tables you can grep — great for fast triage
  before deep analysis.
- It complements [Volatility](volatility.md) rather than replacing it: MemProcFS
  is faster for browsing/triage, Volatility has a wider, scriptable plugin set for
  specific analysis.
- Supports **live** analysis and even RAM acquisition via PCILeech hardware
  (FPGA) — see the ufrisk PCILeech project.
- Wiki with the full filesystem layout and API docs:
  https://github.com/ufrisk/MemProcFS/wiki
