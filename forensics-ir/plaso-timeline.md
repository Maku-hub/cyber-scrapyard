# Plaso (log2timeline / psort)

> The engine behind super-timelines: parse timestamps from hundreds of artifact
> types across a whole image into one normalized timeline, then filter and export
> the slice that matters for your investigation window.

- **Link:** https://github.com/log2timeline/plaso
- **Type:** open source
- **Platform:** cross-platform (Python; Docker image recommended)

## Description

A "super-timeline" merges every timestamped artifact on a system — filesystem
`$MFT`/`$UsnJrnl`, event logs, registry, browser history, prefetch, LNK files,
and many more — into a single chronological view, so you can see exactly what
happened in what order. Plaso is the tool that builds it. `log2timeline.py`
recursively runs its parsers over a disk image or directory and stores the
results in a Plaso storage file; `psort.py` then sorts, filters, and exports that
data (usually to CSV) for analysis in a spreadsheet, [Timesketch](timesketch.md),
or Timeline Explorer.

## Installation

```bash
# Recommended: run the official Docker image (avoids dependency pain)
docker pull log2timeline/plaso

# Debian/Ubuntu via the GIFT PPA
sudo add-apt-repository ppa:gift/stable
sudo apt update && sudo apt install plaso-tools
```

## Usage examples

```bash
# Parse a whole disk image into a Plaso storage file (auto-detects artifacts)
log2timeline.py --storage-file timeline.plaso disk.raw

# Parse a mounted directory / triage collection instead of a raw image
log2timeline.py --storage-file timeline.plaso /mnt/evidence/

# Show what was collected and parser stats
pinfo.py timeline.plaso

# Export the full timeline to CSV (l2tcsv format)
psort.py -w timeline.csv timeline.plaso

# Filter to an incident window during export
psort.py -w window.csv timeline.plaso \
  "date > '2026-07-01 00:00:00' AND date < '2026-07-05 00:00:00'"

# Only run selected parsers for a faster, targeted timeline
log2timeline.py --parsers "winevtx,winreg,mft" \
  --storage-file logs.plaso disk.raw
```

## Notes & references

- Full parsing of a large image is **slow and huge** — scope with `--parsers`,
  restrict the time window in `psort.py`, or feed it a
  [KAPE](kape.md)/triage collection instead of a full image.
- Timestamps are normalized to UTC; set `--timezone` for correct source
  interpretation and note the offset in your report.
- Plaso output is the standard feed into [Timesketch](timesketch.md) for
  collaborative, searchable timelines.
- Docs and parser list: https://plaso.readthedocs.io
