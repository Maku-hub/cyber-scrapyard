# Maltego

> A visual link-analysis platform: pull relationships between people, domains,
> emails, infrastructure, and social accounts onto an interactive graph.

- **Link:** https://www.maltego.com
- **Type:** commercial (free Community Edition with limits)
- **Platform:** cross-platform desktop app (Java); cloud offering available

## Description

Maltego turns scattered OSINT into a picture. You start from an entity (a
domain, person, email, IP, company) and run "transforms" — queries against data
sources — that expand it into related entities, drawing the links as you go.
Because the results are a live graph, it's excellent for understanding how
pieces of an organisation or an investigation connect: which subdomains share an
IP, which email addresses tie back to a person, which infrastructure a threat
actor reuses. It's the go-to tool when the *relationships* matter as much as the
individual facts.

## Installation

- Download the client from https://www.maltego.com/downloads/ and sign in with a
  free Maltego account (Community Edition) or a paid licence.
- Community Edition works for learning but caps results per transform and is
  non-commercial only.

## Usage examples

Maltego is GUI-driven, so the "commands" are graph operations:

```text
# Typical investigation flow inside the client:
1. Drag an entity (Domain, Person, Email Address, IP, ...) onto the graph.
2. Right-click it and run a Transform (or a Machine that chains transforms).
3. New related entities appear and are linked automatically.
4. Select any node and expand further to pivot deeper.
5. Export the graph/report for documentation.
```

Common starting transforms:

```text
# From a Domain: find DNS names, MX/NS records, and related IPs
Domain -> DNS Name / MX / NS / To IP Address

# From an Email Address: find breaches, social profiles, related domains
Email -> "To Person", "verify email", breach lookups (via hub items)

# From a Person / alias: pivot to social media accounts and documents
```

## Notes & references

- Extra data sources are installed from the **Transform Hub** (many free, some
  paid — e.g. Shodan, Have I Been Pwned, VirusTotal, social media).
- Standard transforms for domains/DNS/infrastructure overlap with
  [Amass](../recon-scanning/amass.md) and [subdomain
  tooling](../recon-scanning/subdomain-enumeration.md) — Maltego adds the visual
  correlation layer on top.
- Great for reporting: the graph itself is often the deliverable.
- Docs & training: https://docs.maltego.com
