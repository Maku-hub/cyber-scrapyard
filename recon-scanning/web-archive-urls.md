# Web Archive URLs

> Mine known URLs for a domain from public archives (Wayback Machine, Common
> Crawl, and friends) before you crawl or fuzz — free endpoints someone else
> already recorded for you.

- **Link:** see per-tool links below
- **Type:** open source
- **Platform:** cross-platform (Go)

## Description

Before spending time and traffic crawling a target, ask what's already been
seen. Archives like the Wayback Machine and Common Crawl have indexed years of
URLs — old endpoints, parameters, `.js` files, admin paths, and now-dead pages
that still hint at the app's structure. These tools query those indexes and
dump every URL they know for a domain, giving you a passive seed list of
attack surface at zero cost to the target. Feed the results into a live-host
prober, a crawler, or a fuzzer. Both tools do essentially the same job with
slightly different sources, so people often run both and dedupe.

## Installation

```bash
# gau (getallurls) — Wayback, Common Crawl, OTX, URLScan (Go)
go install github.com/lc/gau/v2/cmd/gau@latest

# waybackurls — Wayback Machine only, minimal and fast (Go)
go install github.com/tomnomnom/waybackurls@latest
```

## Usage examples

### gau — pull URLs from multiple archive sources

```bash
# Fetch all known URLs for a domain
gau example.com

# Include subdomains and write to a file
gau --subs example.com | tee urls.txt

# Only keep specific file extensions (e.g. JS and JSON)
gau example.com | grep -E '\.js(on)?($|\?)'

# Feed a list of domains on stdin
cat domains.txt | gau --threads 5
```

### waybackurls — Wayback Machine, quick and simple

```bash
# Fetch every URL the Wayback Machine has for a domain
waybackurls example.com

# Run over several domains and dedupe
cat domains.txt | waybackurls | sort -u > wb.txt
```

### Combine, dedupe, and use

```bash
# Merge both tools' output into one unique URL list
(gau --subs example.com; waybackurls example.com) | sort -u > all-urls.txt

# Extract just the paths with parameters (good fuzzing candidates)
sort -u all-urls.txt | grep '=' | sort -u > params.txt
```

## Notes & references

- These are **passive** — the queries hit the archives, not the target — but the
  URLs are historical: many will 404. Confirm which are live by piping through
  [httpx](httpx.md) before acting on them.
- Great input for a crawler: seed [Katana](../web-app-security/katana.md) with
  the archived URLs, then let it discover what's currently reachable.
- Great input for a fuzzer: extract parameters and paths, then hammer them with
  [ffuf](../web-app-security/ffuf.md) or test values with your proxy.
- `gau` also reads from AlienVault OTX and URLScan, so it usually returns more
  than `waybackurls` alone; running both and `sort -u` loses nothing.
- Tool homes: gau https://github.com/lc/gau ·
  waybackurls https://github.com/tomnomnom/waybackurls
