# Web Screenshotting (Visual Triage)

> Bulk-screenshot a list of live hosts so you can eyeball hundreds of web apps
> at a glance instead of opening each one by hand.

- **Link:** see per-tool links below
- **Type:** open source
- **Platform:** cross-platform (Go / Python)

## Description

After probing which hosts serve HTTP, you're often left with hundreds or
thousands of live URLs. Opening each in a browser is hopeless. Screenshotting
tools drive a headless browser over the whole list and produce a gallery of
thumbnails, so you can spot the interesting targets in minutes — default login
pages, forgotten admin panels, error pages leaking stack traces, dev/staging
environments, and anything that just looks out of place. This "visual triage"
step turns a wall of URLs into a prioritised shortlist. Both tools below do the
same core job; pick by ecosystem and report style.

## Installation

```bash
# gowitness — modern Go screenshotter with a searchable report/DB
go install github.com/sensepost/gowitness@latest

# EyeWitness — classic tool, also categorises services and grabs headers
git clone https://github.com/RedSiege/EyeWitness
cd EyeWitness/Python/setup && sudo ./setup.sh
```

## Usage examples

### gowitness — screenshot and browse a report

```bash
# Screenshot a single URL
gowitness single https://example.com

# Screenshot every URL in a file (one per line)
gowitness scan file -f urls.txt

# Serve the interactive report to review results in a browser
gowitness report server
```

### EyeWitness — screenshot with service categorisation

```bash
# Screenshot a list of web URLs and open the HTML report when done
eyewitness --web -f urls.txt --open

# Set a per-host timeout and prepend both http/https to bare hosts
eyewitness --web -f hosts.txt --timeout 30 --prepend-https
```

## Notes & references

- Run this **after** confirming live web servers with [httpx](httpx.md) — feed
  the deduped URL list straight in so you only screenshot things that respond.
- gowitness stores results in a database and has a good searchable web report;
  handy for large scopes you'll revisit.
- EyeWitness additionally fingerprints the service type and can suggest default
  credentials to try — useful for quick wins on management interfaces.
- All drive a headless Chrome/Chromium — install a browser if the tool doesn't
  bundle one.
- Tool homes: gowitness https://github.com/sensepost/gowitness ·
  EyeWitness https://github.com/RedSiege/EyeWitness
