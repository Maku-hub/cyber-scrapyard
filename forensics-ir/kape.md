# KAPE

> Kroll Artifact Parser and Extractor: collect just the forensically valuable
> files from a live or mounted Windows system in seconds, then run parser modules
> over them — the standard rapid-triage tool.

- **Link:** https://www.kroll.com/kape
- **Type:** freeware (free for use; by Kroll / Eric Zimmerman)
- **Platform:** Windows

## Description

Full disk images are slow to acquire and analyze. KAPE flips the model: instead
of everything, it grabs **only the artifacts that matter** (registry hives, event
logs, prefetch, `$MFT`, browser data, etc.) using **Targets**, then runs
**Modules** — external parsers like [Eric Zimmerman's tools](eric-zimmerman-tools.md)
— to turn that collection into analysis-ready CSV/JSON. It can run against a live
system, a mounted image, or a remote endpoint, making it the fastest way to get
answers early in an incident. It has both a CLI (`kape.exe`) and a GUI
(`gkape.exe`).

## Installation

Request the download from Kroll (free, registration required) and extract the
portable folder: https://www.kroll.com/kape . Run from removable media for live
collection.

## Usage examples

```bash
# Collect a broad triage set from C: into a timestamped output folder
kape.exe --tsource C: --target !SANS_Triage --tdest E:\collection

# Collect only event logs and registry (specific targets)
kape.exe --tsource C: --target EventLogs,RegistryHives --tdest E:\out

# Collect AND parse in one pass: run modules over what was collected
kape.exe --tsource C: --target !SANS_Triage --tdest E:\out ^
         --module !EZParser --mdest E:\out\parsed

# List available targets / modules
kape.exe --tlist .
kape.exe --mlist .
```

## Typical workflow

1. **Collect** — run KAPE with the `!SANS_Triage` compound target against the
   live drive (or a mounted image), writing to external media.
2. **Parse** — run the `!EZParser` module to fire Eric Zimmerman's parsers over
   the collection, producing CSVs.
3. **Analyze** — open the parsed output in **Timeline Explorer** and pivot on the
   incident window; hunt event logs with [Chainsaw](log-and-triage.md).

## Notes & references

- **Targets** define *what to collect*; **Modules** define *what to run* on it.
  Both are community-maintained YAML/text files — you can write your own.
- KAPE preserves timestamps and metadata during collection (it uses raw disk
  reads to grab locked files like the registry and `$MFT`).
- Compound targets like `!SANS_Triage` bundle the common artifacts; `!EZParser`
  is the usual go-to module.
- For collection at scale across many endpoints, see
  [Velociraptor](log-and-triage.md).
