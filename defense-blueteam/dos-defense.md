# DoS / DDoS Defence

> Understanding denial-of-service attack classes (volumetric L4 vs application
> L7) so you can size, detect, and mitigate them — with slowhttptest for
> *authorised* resilience testing of your own services.

- **Link:** https://github.com/shekyan/slowhttptest
- **Type:** concept reference + open-source testing tool
- **Platform:** cross-platform

## Description

This is a themed, defence-oriented page. Denial-of-service attacks try to exhaust
a resource so legitimate users can't be served. Knowing which resource is under
pressure tells you where to defend.

## Attack classes

- **Volumetric (Layer 4)** — flood the pipe. Measured in **Mb/s (or Gb/s)**;
  the goal is to saturate bandwidth (UDP/ICMP floods, amplification/reflection).
  Mitigation lives upstream: ISP/CDN scrubbing, anycast, blackholing.
- **Application (Layer 7)** — exhaust the application, not the link. Two common
  flavours:
  - **Socket exhaustion / slowloris-style** — hold every available connection
    open with slow or partial requests, consuming all worker sockets.
  - **HTTP flood / packet-per-second** — measured in **requests/second (rps)**;
    cheap requests that force expensive server-side work, burning CPU.

## Defensive measures

- Tune the HTTP server / load balancer: connection and request-rate limits,
  aggressive client timeouts, a cap on concurrent connections per IP, and a
  bound on request header/body read time (kills slowloris-style attacks).
- Put a CDN / reverse proxy / WAF in front (see [ModSecurity](modsecurity.md))
  for rate limiting and caching.
- Detect and alert with IDS/IPS — [Snort](snort.md) / [Suricata](suricata.md)
  can alert on, and even drop, flood patterns via thresholds.

## Usage examples

`slowhttptest` lets you test whether **your own** server survives slow L7
attacks. Only run it against systems you own or are authorised to test.

```bash
# Install (Debian/Kali/Ubuntu)
sudo apt install slowhttptest
```

```bash
# Slowloris test: hold 1000 connections open, sending headers slowly
slowhttptest -c 1000 -H -i 10 -r 200 -u http://your-server.example -x 24 -p 3

# Slow POST (slow message body) test
slowhttptest -c 1000 -B -i 10 -r 200 -u http://your-server.example

# Slow Read test — advertise a tiny receive window to stall responses
slowhttptest -c 1000 -X -r 200 -u http://your-server.example
```

Key flags: `-H` slow headers, `-B` slow body, `-X` slow read, `-c` connections,
`-r` connection rate, `-i` interval between data, `-u` target URL. It writes an
HTML/CSV report showing when the service became unavailable.

## Notes & references

- Interpret the report by the moment "service available" flips to NO — that's
  your concurrency ceiling; raise it with timeouts and connection limits.
- slowhttptest: https://github.com/shekyan/slowhttptest
- Nginx hardening: `limit_conn`, `limit_req`, `client_body_timeout`,
  `client_header_timeout`. Apache: `mod_reqtimeout`, `mod_qos`.
- Real volumetric DDoS cannot be absorbed on a single host — plan for upstream
  scrubbing (CDN / provider) before you need it.
