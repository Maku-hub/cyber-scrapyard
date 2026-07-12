# People & Username OSINT

> Tools for finding a person online: hunt a username across hundreds of sites,
> and check which services an email address is registered on.

- **Link:** see per-tool links below
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

Much of an investigation comes down to linking a person to their online
presence. Given a username, these tools check hundreds of platforms to see where
that handle exists; given an email, they reveal which services it's registered
with — all without alerting the target. That's useful for authorised
investigations, social-engineering assessments (mapping an organisation's
employees), and understanding your own exposure. Always stay within legal and
ethical bounds: this is for authorised, defensive, or consented use.

## Installation

```bash
# Sherlock — username search across social networks
pipx install sherlock-project        # or: pip install sherlock-project

# Maigret — Sherlock-style search with richer profiling/reports
pipx install maigret

# holehe — check which sites an email is registered on
pipx install holehe
```

## Usage examples

### Sherlock — find a username across sites

```bash
# Search a single username across hundreds of platforms
sherlock johndoe

# Check several usernames and save results to a folder
sherlock johndoe janedoe --folderoutput results/

# Only report accounts that were actually found, output as CSV
sherlock johndoe --print-found --csv
```

### Maigret — username OSINT with reporting

```bash
# Search a username and generate an HTML/PDF report
maigret johndoe --html

# Pull extra info (tags, IDs) and search a specific set of sites
maigret johndoe --tags photo,dating
```

### holehe — email-to-account discovery

```bash
# Find which services an email address is registered on
holehe target@example.com

# Only show sites where the email is used
holehe target@example.com --only-used
```

### WhatsMyName — the underlying data project

```text
# WhatsMyName maintains the community username-enumeration dataset that many
# tools build on. Use the web UI or the JSON site list:
# https://whatsmyname.app  ·  https://github.com/WebBreacher/WhatsMyName
```

## Notes & references

- Results have false positives/negatives — always verify a hit manually before
  relying on it.
- Combine with breach/email tools like Have I Been Pwned and
  [theHarvester](theharvester.md) to enrich a profile from an email or name.
- Keep it legal: only investigate targets you're authorised to, and respect
  privacy laws (GDPR, etc.).
- Tool homes: Sherlock https://github.com/sherlock-project/sherlock ·
  Maigret https://github.com/soxoj/maigret ·
  holehe https://github.com/megadose/holehe ·
  WhatsMyName https://github.com/WebBreacher/WhatsMyName
