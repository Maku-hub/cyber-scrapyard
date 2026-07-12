# Have I Been Pwned

> Check whether an email address, phone number, or password has appeared in a
> known data breach — the go-to service for breach-exposure lookups.

- **Link:** https://haveibeenpwned.com (API docs: https://haveibeenpwned.com/API/v3)
- **Type:** freemium (free web search; paid API key for automated queries)
- **Platform:** web app + REST API

## Description

Have I Been Pwned (HIBP), run by Troy Hunt, aggregates billions of records from
publicly disclosed breaches into one searchable index. Paste an email address on
the site and it tells you which breaches it appeared in and what data was
exposed (passwords, addresses, etc.). For OSINT it confirms that an account
existed on a given service and hints at where to dig next; for defenders it's a
quick exposure check for staff and a way to enforce that users never pick a
password that has already leaked. The "Pwned Passwords" range API is especially
useful because it uses k-anonymity, so you can check a password hash without ever
sending the full hash.

## Usage examples

### Web

```text
# 1. Open https://haveibeenpwned.com
# 2. Enter the email address you're authorised to check and press "pwned?"
# 3. Review the list of breaches and the data classes each exposed
# 4. Use https://haveibeenpwned.com/Passwords to test a candidate password
# 5. Subscribe an address at https://haveibeenpwned.com/NotifyMe for future alerts
```

### API

```bash
# Look up all breaches for an account (requires an API key header)
curl -s -H "hibp-api-key: YOUR_API_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com?truncateResponse=false"

# List every breach in the system (no key needed)
curl -s "https://haveibeenpwned.com/api/v3/breaches"

# Pwned Passwords via k-anonymity: send only the first 5 SHA-1 chars,
# then grep the returned suffixes for the rest of your hash (no key needed)
curl -s "https://api.pwnedpasswords.com/range/21BD1"
```

## Notes & references

- Account lookups are rate-limited and require a paid API key; the breach list
  and Pwned Passwords range endpoints are free and keyless.
- k-anonymity means the full password/hash never leaves your machine — only a
  5-character SHA-1 prefix is sent.
- Absence from HIBP is not proof of safety: it only covers breaches that have
  been loaded into the service.
- Only look up addresses you own or are authorised to investigate; respect
  privacy law (GDPR, etc.).
- Pairs well with [people & username OSINT](people-username-osint.md) and
  [theHarvester](theharvester.md) to enrich a profile from an email.
