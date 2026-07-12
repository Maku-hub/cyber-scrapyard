# ExifTool

> Read, write, and strip metadata from images, documents, and media — the
> reference tool for pulling hidden EXIF/IPTC/XMP data out of files.

- **Link:** https://github.com/exiftool/exiftool (site: https://exiftool.org)
- **Type:** open source
- **Platform:** cross-platform (Perl; standalone Windows/macOS binaries)

## Description

ExifTool parses the metadata embedded in almost any file type — photos, PDFs,
Office documents, videos — and surfaces details their creators rarely think
about: GPS coordinates, camera serial numbers, software versions, author names,
timestamps, and edit history. In OSINT that metadata can geolocate a photo,
attribute a document to a person or organisation, or reveal internal usernames
and file paths. It also writes and removes tags, so it doubles as a tool for
scrubbing metadata before you publish files of your own.

## Installation

```bash
sudo apt install libimage-exiftool-perl   # Debian/Kali/Ubuntu
brew install exiftool                       # macOS
# Windows: download the standalone .exe from https://exiftool.org
```

## Usage examples

```bash
# Dump all metadata from a file
exiftool photo.jpg

# Show only GPS coordinates (great for geolocating a photo)
exiftool -gps:all -c "%.6f" photo.jpg

# Extract selected fields: author, creator software, timestamps
exiftool -Author -Creator -CreateDate -ModifyDate document.pdf

# Recurse a directory and output everything as JSON for parsing
exiftool -r -json ./images/ > metadata.json

# Strip ALL metadata (sanitise a file before sharing)
exiftool -all= cleaned.jpg
```

## Notes & references

- Common fields worth checking: `GPSLatitude`/`GPSLongitude`, `Make`/`Model`,
  `Software`, `Author`/`Creator`, `CreateDate`, and PDF `Producer`.
- `-all=` removes metadata but leaves a `_original` backup unless you add
  `-overwrite_original`.
- Great for CTFs and phishing analysis — Office/PDF files often leak internal
  usernames, template paths, and tooling versions.
- Full tag documentation: https://exiftool.org/TagNames/
- Leaked usernames/paths pulled from documents feed
  [people & username OSINT](people-username-osint.md); ExifTool features in the
  [External Recon & OSINT](../scenarios/external-recon-osint.md) scenario.
