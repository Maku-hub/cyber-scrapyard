# OWASP Top 10

> The Open Worldwide Application Security Project's flagship awareness document:
> the ten most critical security risks to web applications, refreshed
> periodically from real-world data. A baseline every web tester and developer
> should know.

- **Link:** https://owasp.org/www-project-top-ten/
- **Type:** free / open standard

## Description

The OWASP Top 10 is a consensus list of the categories of web application
weakness that cause the most damage in practice. It is not a checklist of every
bug, but a prioritized starting point for testing and secure development. It
underpins much of the work in [Web Application Security](../web-app-security/).

## The categories (2021 edition)

1. **A01 Broken Access Control** — users acting outside their intended
   permissions.
2. **A02 Cryptographic Failures** — weak or missing protection of data in transit
   and at rest.
3. **A03 Injection** — untrusted input interpreted as code/query (SQLi, command
   injection, XSS).
4. **A04 Insecure Design** — missing or flawed security controls by design.
5. **A05 Security Misconfiguration** — default settings, verbose errors, unneeded
   features left enabled.
6. **A06 Vulnerable and Outdated Components** — using libraries/frameworks with
   known flaws.
7. **A07 Identification and Authentication Failures** — weak login, session, or
   credential handling.
8. **A08 Software and Data Integrity Failures** — unverified updates, insecure
   deserialization, supply-chain issues.
9. **A09 Security Logging and Monitoring Failures** — attacks going undetected.
10. **A10 Server-Side Request Forgery (SSRF)** — server coerced into making
    unintended requests.

## Notes & references

- The list is periodically re-ranked from aggregated vulnerability data; always
  check the current edition at the link above.
- OWASP also publishes the [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
  and the [ASVS](https://owasp.org/www-project-application-security-verification-standard/)
  for deeper, methodical testing.
- Several walkthroughs in [Sample Walkthroughs](sample-walkthroughs.md) map onto
  these categories (misconfiguration, vulnerable components, access control).
