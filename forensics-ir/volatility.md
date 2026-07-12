# Volatility

> The standard open-source memory-forensics framework: parse a RAM capture to
> recover running processes, network connections, injected code, loaded drivers,
> and credentials. Volatility 3 is the current generation.

- **Link:** https://github.com/volatilityfoundation/volatility3
- **Type:** open source (Volatility Software License / custom)
- **Platform:** cross-platform (Python 3)

## Description

Memory holds what disk doesn't: decrypted data, injected/fileless code, live
network state, command history, and credentials. Volatility reads a raw memory
image and, using OS-specific plugins, reconstructs the state of the system at
capture time. **Volatility 3** replaces the old per-profile model with automatic
symbol resolution (no more picking a `--profile`) and a cleaner plugin namespace
(`windows.*`, `linux.*`, `mac.*`). It's the first thing you run against a RAM
capture in most investigations.

## Installation

```bash
pipx install volatility3          # or: pip install volatility3
# Run via the installed entry point:
vol -h
# (Some setups run it as: python3 vol.py -h)
```

## Usage examples

```bash
# Auto-detect the OS and list running processes (tree view too)
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree

# Find hidden/terminated processes by scanning pool tags
vol -f memory.raw windows.psscan

# Network connections and listening sockets
vol -f memory.raw windows.netscan

# Command lines of processes (spot suspicious args)
vol -f memory.raw windows.cmdline

# Detect injected/unmapped executable memory (classic injection hunt)
vol -f memory.raw windows.malfind

# DLLs loaded by a process / handles it holds
vol -f memory.raw windows.dlllist --pid 1234
vol -f memory.raw windows.handles --pid 1234

# Dump a process's memory pages to disk for further RE
vol -f memory.raw windows.memmap --pid 1234 --dump
# Dump cached/memory-mapped file objects (not process memory)
vol -f memory.raw windows.dumpfiles --pid 1234

# Registry: list hives, then read a key
vol -f memory.raw windows.registry.hivelist
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Linux example
vol -f memory.lime linux.pslist
```

## Notes & references

- **Acquire** memory with a dedicated tool first (FTK Imager, WinPmem, DumpIt,
  or LiME on Linux) — see [FTK Imager](ftk-imager.md).
- `malfind` + `pslist`/`psscan` diffing is the bread-and-butter injection hunt;
  `dumpfiles`/`vadinfo` let you carve the suspicious region out for
  [reverse engineering](../reverse-engineering-malware/).
- Volatility 3 auto-fetches symbol tables (ISF) online; for offline use, cache
  them locally.
- Docs & plugin list: https://volatility3.readthedocs.io
