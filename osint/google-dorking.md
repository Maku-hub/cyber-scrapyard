# Google Dorking (Google Hacking)

> Advanced search-engine operators that surface exposed files, login pages, and
> misconfigurations — plus the Google Hacking Database of ready-made queries.

- **Link:** Google Hacking Database (GHDB): https://www.exploit-db.com/google-hacking-database
- **Type:** free (technique + public query database)
- **Platform:** any search engine (Google, Bing, DuckDuckGo)

## Description

"Google dorking" is the practice of combining search operators to make a search
engine reveal things that were never meant to be found — directory listings,
config files, backups, credentials, camera feeds, and admin panels indexed from
the open web. Because it queries the search engine and never the target, it's
purely passive reconnaissance. The Google Hacking Database (GHDB), maintained on
Exploit-DB, is a categorised, community-curated collection of proven dork queries
you can copy and adapt. Use it to understand what an organisation has
accidentally exposed to the public internet.

## Common operators

```text
# Restrict results to one site or domain
site:example.com

# Match a word in the page title / URL / body text
intitle:"index of"          allintitle:admin login
inurl:admin                 allinurl:auth login
intext:"password"

# Filter by file type
filetype:pdf                ext:sql

# Cached copy and related sites
cache:example.com           related:example.com

# Exclude terms, combine with boolean OR, and group
site:example.com -www
site:example.com (filetype:xls OR filetype:csv)
```

## Usage examples

```text
# Open directory listings on a target domain
site:example.com intitle:"index of"

# Exposed database dumps or SQL backups
site:example.com ext:sql intext:INSERT INTO

# Login / admin portals across a domain
site:example.com inurl:(login OR admin OR signin)

# Documents that may leak internal data
site:example.com filetype:pdf OR filetype:docx OR filetype:xlsx

# Config and environment files accidentally published
site:example.com (ext:env OR ext:ini OR ext:conf) intext:password

# Public GHDB example: unprotected network cameras
intitle:"Live View / - AXIS"
```

## Notes & references

- Browse and search ready-made dorks in the GHDB:
  https://www.exploit-db.com/google-hacking-database
- Operators differ slightly per engine; Bing supports `ip:` and `contains:`,
  which Google does not.
- Google may throttle or CAPTCHA aggressive dorking — slow down, and consider
  automation tools that respect rate limits.
- Only dork targets you're authorised to assess; accessing exposed data you find
  can still be illegal even though the query itself is passive.
- Related passive sources are listed on the [OSINT overview](README.md); dorking
  features in the [External Recon & OSINT](../scenarios/external-recon-osint.md)
  scenario.
