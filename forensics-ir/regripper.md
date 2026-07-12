# RegRipper

> Harlan Carvey's plugin-driven registry parser: point it at a hive and it pulls
> out the forensically interesting keys — persistence, USB history, user activity,
> network settings — without you hunting through the raw registry by hand.

- **Link:** https://github.com/keydet89/RegRipper3.0
- **Type:** open source
- **Platform:** cross-platform (Perl; Windows GUI `rr.exe`)

## Description

The Windows registry is a goldmine of forensic evidence, but it's a sprawling
binary database. RegRipper runs a library of small **plugins** against a given
hive (SYSTEM, SOFTWARE, NTUSER.DAT, SAM, etc.), each of which extracts and
formats one category of artifact — Run keys and services (persistence), USBSTOR
(device history), TypedURLs/RecentDocs (user activity), ShimCache/Amcache
(execution), network profiles, and more. It turns hours of manual key-walking
into a single report and is a staple of Windows incident response.

## Installation

```bash
# Clone the repo (Perl-based; run rip.pl on Linux/macOS)
git clone https://github.com/keydet89/RegRipper3.0.git

# On Windows, use the bundled GUI (rr.exe) or CLI (rip.exe) from the release zip.
# Extract hives first with FTK Imager or from a KAPE collection.
```

## Usage examples

```bash
# List all available plugins
rip.pl -l

# Run a single plugin against a hive (e.g. Run-key persistence in SOFTWARE)
rip.pl -r SOFTWARE -p run

# USB device history from the SYSTEM hive
rip.pl -r SYSTEM -p usbstor

# Run an entire profile (a curated bundle of plugins) against a hive
rip.pl -r NTUSER.DAT -f ntuser > ntuser_report.txt

# Guess the hive type and run all applicable plugins
rip.pl -r SAM -a > sam_report.txt
```

## Notes & references

- **Profiles** (`-f`) bundle the sensible plugin set per hive type
  (`system`, `software`, `ntuser`, `sam`, `security`) — the quickest way to a
  full report.
- Grab hives from a mounted image or a [KAPE](kape.md)/FTK collection; don't parse
  a live `C:\Windows\System32\config` copy that Windows has locked.
- Complements [Eric Zimmerman's tools](eric-zimmerman-tools.md) (Registry Explorer
  / RECmd) — RegRipper is fast for scripted reports, RegistryExplorer for
  interactive deep dives and deleted-key recovery.
- Keys like ShimCache/Amcache and UserAssist feed execution evidence into your
  [Plaso timeline](plaso-timeline.md).
- Plugin docs and author's blog: https://github.com/keydet89/RegRipper3.0 and
  https://windowsir.blogspot.com
