# PhoneInfoga

> OSINT reconnaissance from a phone number: identify the country, carrier and
> line type, then pivot into search-engine footprinting to find where the
> number appears online.

- **Link:** https://github.com/sundowndev/phoneinfoga
- **Type:** open source
- **Platform:** cross-platform (Go; also Docker)

## Description

PhoneInfoga is one of the most complete tools for the phone-number data type —
the piece most OSINT workflows overlook. Given a number in international format,
it validates and parses it (country, area, carrier, and whether it's mobile,
fixed-line or VoIP), then runs "scanners" that build search-engine dorks and
query reputation/reverse-lookup sources to surface where that number has been
posted: listings, social profiles, leaked documents, spam databases. It doesn't
call or text the target, so it's a passive first step for tracing a number back
to a person or business during authorised investigations.

## Installation

```bash
# Run without installing via Docker
docker run --rm -it sundowndev/phoneinfoga scan -n "+14152229999"

# Or install the Go binary
go install github.com/sundowndev/phoneinfoga/v2@latest
```

## Usage examples

```bash
# Scan a single number (always use international +country format)
phoneinfoga scan -n "+14152229999"

# Scan several numbers at once
phoneinfoga scan -n "+14152229999, +442079460000"

# Launch the local web UI + REST API for interactive lookups
phoneinfoga serve -p 8080
```

## Notes & references

- Always supply the number in **international E.164 format** (`+<country><number>`)
  or parsing fails.
- Some scanners rely on third-party services that need API keys (e.g. Numverify)
  — set them via environment variables to enrich results; the local scanner
  works without any.
- Output is a set of search-engine dorks and leads to follow **manually** — it
  points you at pages, it doesn't confirm ownership. Verify every hit.
- Pivot from a confirmed number: run the name/handle through
  [people & username OSINT](people-username-osint.md) and check breach exposure
  with [Have I Been Pwned](haveibeenpwned.md) (which also indexes phone numbers).
- Stay legal: only investigate numbers you're authorised to, and respect privacy
  laws (GDPR and local equivalents).
- Docs: https://sundowndev.github.io/phoneinfoga/
