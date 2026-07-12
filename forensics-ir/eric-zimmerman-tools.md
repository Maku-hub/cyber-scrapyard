# Eric Zimmerman's Tools

> A free suite of fast, focused Windows forensic artifact parsers — Amcache,
> ShellBags, `$MFT`, Prefetch, jump lists, registry, and more — the DFIR
> community's default toolkit for reconstructing Windows activity.

- **Link:** https://ericzimmerman.github.io
- **Type:** freeware (open source; .NET)
- **Platform:** Windows (most tools run on .NET; some cross-platform builds exist)

## Description

Windows records an enormous amount of evidence in obscure artifacts, and Eric
Zimmerman's tools ("EZ Tools") parse them into clean, analyzable CSV/JSON. Each
tool does one artifact well and fast. Most have a command-line parser (great for
scripting/KAPE) plus a companion GUI, **Timeline Explorer**, for slicing the CSV
output. They're the standard way to answer "what programs ran, what files were
opened, and what folders were browsed" on a Windows host.

## The core tools

| Tool | Artifact | Answers |
| --- | --- | --- |
| **AmcacheParser** | `Amcache.hve` | Evidence of program presence/execution (paths, SHA-1) |
| **AppCompatCacheParser** | ShimCache | Programs that existed/ran (registry) |
| **PECmd** | Prefetch (`*.pf`) | Program execution, run count, last-run times |
| **SBECmd** | ShellBags (registry) | Folders a user browsed (incl. deleted/removable) |
| **MFTECmd** | `$MFT`, `$J`, `$LogFile` | Full file listing, timestamps, and journal activity |
| **RECmd** | Registry hives | Batch registry parsing with plugins |
| **LECmd** | LNK files | Shortcut targets — recently accessed files |
| **JLECmd** | Jump Lists | Recently used files/apps per taskbar item |
| **RBCmd** | Recycle Bin (`$I`) | Deleted-file metadata |
| **EvtxECmd** | `.evtx` event logs | Normalized event-log output (with maps) |

## Installation

```bash
# Download "Get-ZimmermanTools" or the individual tools:
#   https://ericzimmerman.github.io
# The PowerShell helper downloads/updates all tools:
#   .\Get-ZimmermanTools.ps1
```

## Usage examples

```bash
# Parse Amcache into CSV
AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve --csv .\out

# Prefetch: parse a folder of .pf files (execution evidence)
PECmd.exe -d C:\Windows\Prefetch --csv .\out

# Parse the $MFT for a full timestamped file listing
MFTECmd.exe -f .\$MFT --csv .\out

# ShellBags for a user (folder-browsing history)
SBECmd.exe -d C:\Users\jdoe\ --csv .\out

# Then open any CSV in Timeline Explorer for filtering/sorting.
```

## Notes & references

- Output is CSV/JSON by design — pull it into **Timeline Explorer** (also by EZ)
  or merge into a super-timeline.
- These parsers are the backbone of many [KAPE](kape.md) modules — KAPE collects
  the artifacts, EZ Tools parse them.
- Poster/cheatsheets and SANS references cover which artifact answers which
  question; the site links Eric's training.
- For event-log hunting at scale, pair EvtxECmd with
  [Chainsaw](log-and-triage.md).
