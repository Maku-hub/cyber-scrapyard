# Autopsy & The Sleuth Kit

> Open-source disk forensics: **The Sleuth Kit (TSK)** is the command-line
> filesystem-analysis engine, and **Autopsy** is the full-featured GUI built on
> top of it — the free go-to for examining disk images.

- **Link:** https://github.com/sleuthkit/autopsy · TSK: https://github.com/sleuthkit/sleuthkit
- **Type:** open source
- **Platform:** cross-platform (Autopsy GUI is best supported on Windows)

## Description

The Sleuth Kit is a library and set of CLI tools for analyzing disk images and
filesystems (NTFS, FAT/exFAT, ext, HFS+, and more): list files, recover deleted
entries, read the `$MFT`, and walk allocation structures. **Autopsy** wraps all
of that in a case-based GUI with ingest modules that automate the common jobs —
keyword search, hash lookups, web/email artifacts, EXIF, timeline, and file
carving — making it approachable for full investigations without memorizing TSK
commands.

## Installation

```bash
# Autopsy — download the installer (Windows) or package:
#   https://www.autopsy.com/download/

# The Sleuth Kit CLI (Linux):
sudo apt install sleuthkit
```

## Usage examples

The Sleuth Kit CLI is layered by the "layer" of the filesystem it queries:

```bash
# List partitions in a disk image
mmls disk.dd

# List files/directories (including deleted, -d) in a filesystem at an offset
fls -r -o 2048 disk.dd

# Dump a file's content by its inode/MFT number
icat -o 2048 disk.dd 12345 > recovered.docx

# Build a body file, then a timeline of file activity
fls -r -m / -o 2048 disk.dd > bodyfile
mactime -b bodyfile -d > timeline.csv
```

### Autopsy (GUI) workflow

1. **New case** — create a case, add the disk image (or a physical drive) as a
   data source.
2. **Run ingest modules** — enable hash lookup, keyword search, recent activity,
   EXIF, and file carving; let them index the image.
3. **Investigate** — browse the file tree, review carved/deleted files, run
   keyword searches, and inspect the extracted web/email/USB artifacts.
4. **Timeline** — open the Timeline view to see file and artifact activity over
   time; filter to the incident window.
5. **Report** — tag findings and generate an HTML/Excel report.

## Notes & references

- Autopsy ingest modules are extensible (Python/Java) — the community adds
  parsers for many artifact types.
- TSK is the engine under many other tools; learning `fls`/`icat`/`mactime` pays
  off across the DFIR ecosystem.
- Docs: https://sleuthkit.org/autopsy/docs.php and https://wiki.sleuthkit.org
- For RAM (not disk), use [Volatility](volatility.md); for fast triage collection,
  see [KAPE](kape.md).
