# bulk_extractor

> Scans a disk image, file, or directory at high speed and carves out artifacts —
> emails, URLs, credit-card numbers, EXIF, and network packets — ignoring the
> filesystem entirely, so it recovers evidence even from deleted or damaged data.

- **Link:** https://github.com/simsong/bulk_extractor
- **Type:** open source
- **Platform:** cross-platform (Linux/macOS; Windows build available)

## Description

bulk_extractor reads the raw bytes of an image and pulls out interesting content
with pattern **scanners**, without parsing the filesystem. Because it doesn't care
about file boundaries or metadata, it finds artifacts in slack space, unallocated
areas, swap, and partially overwritten files that a file-aware tool would miss.
Each scanner writes a "feature file" (e.g. `email.txt`, `url.txt`, `ccn.txt`) with
the value and its byte offset, plus a **histogram** ranking the most frequent
hits. It's multithreaded and fast, making it a strong first pass for lead
generation early in a case. A companion GUI, **BEViewer**, browses the results.

## Installation

```bash
# Debian/Kali/Ubuntu
sudo apt install bulk-extractor

# Or build from source
git clone --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor && ./bootstrap.sh && ./configure && make && sudo make install
```

## Usage examples

```bash
# Run all default scanners on an image, results into ./out
bulk_extractor -o out disk.raw

# Run only specific scanners (faster and less noisy)
bulk_extractor -o out -e email -e url -e exif disk.raw

# Enable an off-by-default scanner (e.g. WordPress/wordlist) and disable another
bulk_extractor -o out -e wordlist -x accts disk.raw

# Carve straight from a physical device (Linux)
bulk_extractor -o out /dev/sdb

# Inspect the results: feature files + histograms sit in ./out
#   out/email.txt, out/email_histogram.txt, out/url.txt, out/ccn.txt, ...
```

## Notes & references

- **Feature files vs. histograms:** the raw feature file lists every hit with its
  offset; the histogram ranks by frequency — start with the histograms to spot the
  dominant domains, addresses, or accounts.
- The `packets` scanner reconstructs network packets found in memory/swap into a
  PCAP — useful against RAM images and hiberfil.
- False positives are expected (it's pattern-based); treat output as **leads** to
  verify, not conclusions.
- Recovered URLs/emails/IOCs pair well with a [Plaso timeline](plaso-timeline.md)
  and disk analysis in [Autopsy](autopsy-sleuthkit.md).
- Docs and BEViewer: https://github.com/simsong/bulk_extractor/wiki
