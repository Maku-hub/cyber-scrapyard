# APKLeaks

> Scans an APK for leaked secrets, URIs, endpoints and API keys — a fast,
> regex-driven first pass over a mobile app's baked-in strings.

- **Link:** https://github.com/dwisiswant0/apkleaks
- **Type:** open source
- **Platform:** cross-platform (Python 3)

## Description

APKLeaks disassembles an APK and greps the result against a large, tunable set of
patterns for things developers accidentally ship: cloud keys, Firebase/S3 URLs,
API endpoints, tokens and other juicy strings. It's the quick win before manual
review — run it, get a JSON list of hits, and know immediately whether there are
hardcoded credentials or hidden backend endpoints worth chasing in jadx.

## Installation

```bash
# Install via pipx (bundles jadx/apktool extraction under the hood)
pipx install apkleaks

# Or from source
git clone https://github.com/dwisiswant0/apkleaks.git
cd apkleaks && pip install -r requirements.txt
```

## Usage examples

```bash
# Scan an APK with the built-in pattern set
apkleaks -f app.apk

# Write results to a JSON file for triage/reporting
apkleaks -f app.apk -o results.json --json

# Add your own regex patterns (e.g. an internal token format)
apkleaks -f app.apk -p custom-rules.json

# Pass extra args through to the underlying jadx decompiler
apkleaks -f app.apk --args "--threads-count 4 --deobf"
```

## Notes & references

- Output is only as good as the patterns — extend the rules file for org-specific
  secrets, and expect some false positives to filter out.
- Confirm and contextualize hits by opening the app in [jadx](jadx.md); a found
  endpoint often reveals more of the attack surface.
- Complements [MobSF](mobsf.md)'s secret scanning as a fast standalone/CLI check.
- Related: [truffleHog](https://github.com/trufflesecurity/trufflehog) for
  git/filesystem secret scanning.
