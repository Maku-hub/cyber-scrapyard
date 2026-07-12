# GHunt

> Extract public OSINT from a Google account: linked services, profile photos,
> reviews, and more, starting from just an email address.

- **Link:** https://github.com/mxrch/GHunt
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

GHunt investigates the footprint a Google account leaves across Google's own
services. Given a Gmail address, a Google account ID, a phone number, or a
document/photo ID, it pulls back publicly available data such as the account's
display name, profile and cover photos, Google Maps reviews and ratings, calendar
visibility, and which Google services the account is registered on. It's a strong
addition to any people-OSINT workflow because so many identities are anchored to
a Google account. Authentication uses your own cookies, so use it only for
authorised investigations.

## Installation

```bash
# Install via pipx (recommended) or pip
pipx install ghunt

# One-time login: paste your Google account cookies when prompted
ghunt login
```

## Usage examples

```bash
# Investigate a Gmail / Google account by email address
ghunt email target@gmail.com

# Look up a Google account by its numeric gaia ID
ghunt gaia 123456789012345678901

# Pull metadata from a shared Google Drive document ID
ghunt drive 1AbCdEfGhIjKlMnOpQrStUvWxYz

# Export the results to a JSON file for later correlation
ghunt email target@gmail.com --json result.json
```

## Notes & references

- Requires valid Google account cookies (`ghunt login`); results depend on what
  the target has left public in their account settings.
- Some checks are rate-limited by Google — space out queries to avoid temporary
  blocks.
- Combine with [people & username OSINT](people-username-osint.md) and
  [Have I Been Pwned](haveibeenpwned.md) to build a fuller identity profile.
- Only investigate accounts you are authorised to; respect privacy law (GDPR,
  etc.).
