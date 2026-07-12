# API & GraphQL Testing

> A toolbox for testing modern API-driven apps: fish out JWT weaknesses,
> fingerprint GraphQL engines, explore hidden GraphQL schemas, and brute-force
> REST routes from real-world wordlists.

- **Link:** see per-tool links below
- **Type:** open source
- **Platform:** cross-platform

## Description

Most modern targets are less "website" and more "single-page app talking to an
API." That shifts the attack surface: bearer tokens (usually JWTs), REST
endpoints that never appear in the HTML, and GraphQL backends that can leak
their entire schema through introspection. The tools below cover that surface —
attacking token trust, identifying and mapping GraphQL, and discovering REST
routes that directory brute-forcing misses. Pair them with an API client
(Postman or the open-source [Hoppscotch](https://hoppscotch.io)) to craft,
replay, and tweak requests by hand, and with an intercepting proxy like
[Burp Suite](burp-suite.md) or [OWASP ZAP](owasp-zap.md).

## Installation

```bash
# jwt_tool — analyse, tamper and attack JSON Web Tokens (Python)
git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool && pip install -r requirements.txt

# graphw00f — GraphQL server fingerprinting (Python)
git clone https://github.com/dolevf/graphw00f && cd graphw00f && pip install -r requirements.txt

# kiterunner — content discovery built for APIs (Go)
go install github.com/assetnote/kiterunner/cmd/kr@latest

# InQL — GraphQL scanner; runs as a Burp Suite extension (from the BApp Store)
# https://github.com/doyensec/inql
```

## Usage examples

### jwt_tool — inspect and attack JWTs

```bash
# Decode a token and show its header/payload/claims
python3 jwt_tool.py <JWT>

# Run all common attack checks (alg confusion, none, etc.) against an endpoint
python3 jwt_tool.py -t https://api.example.com/me -rh "Authorization: Bearer <JWT>" -M at

# Crack the HMAC signing secret with a wordlist
python3 jwt_tool.py <JWT> -C -d wordlist.txt
```

### graphw00f — fingerprint the GraphQL engine

```bash
# Detect whether an endpoint speaks GraphQL and which implementation it is
python3 main.py -d -f -t https://example.com/graphql
```

### kiterunner — API-aware route discovery

```bash
# Brute-force API routes using the bundled Assetnote route wordlists
kr scan https://api.example.com -w routes-large.kite

# Replay/scan from an OpenAPI/Swagger definition
kr scan https://api.example.com -A=apiroutes-240528 -x 20
```

### InQL — GraphQL introspection & querying

```text
# Load InQL from the Burp BApp Store, point it at the /graphql endpoint, and
# it pulls the schema via introspection and generates ready-to-send queries.
# https://github.com/doyensec/inql
```

## Notes & references

- JWT quick wins: the `alg: none` bypass, HS256/RS256 **algorithm confusion**,
  and weak HMAC secrets — `jwt_tool` automates all three. Learn the token
  structure first at https://jwt.io.
- If introspection is enabled on a GraphQL endpoint you effectively have the
  full API map — dump it with InQL, then hunt for authorization gaps between
  what the schema exposes and what you should be able to reach.
- Knowing the exact GraphQL engine (via `graphw00f`) matters because each has its
  own quirks (batching, aliasing, and denial-of-service via deeply nested queries).
- kiterunner beats generic [ffuf](ffuf.md)/[gobuster](gobuster.md) on APIs
  because its wordlists carry the right method, headers, and body — not just a
  path — so it triggers routes that only answer to `POST`/`PUT` with JSON.
- Seed all of these with endpoints from a crawl ([Katana](katana.md)) or from
  [web archive URLs](../recon-scanning/web-archive-urls.md).
- Study the classes: **OWASP API Security Top 10**
  (https://owasp.org/API-Security/) — BOLA/IDOR dominates real API findings.
- Tool homes: jwt_tool https://github.com/ticarpi/jwt_tool ·
  graphw00f https://github.com/dolevf/graphw00f ·
  InQL https://github.com/doyensec/inql ·
  kiterunner https://github.com/assetnote/kiterunner
