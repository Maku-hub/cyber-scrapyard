# Evilginx2

> Man-in-the-middle reverse-proxy phishing framework that sits between the victim
> and the real login page to capture credentials **and** the authenticated
> session cookie — defeating most non-phishing-resistant MFA.

- **Link:** https://github.com/kgretzky/evilginx2
- **Type:** open source
- **Platform:** cross-platform (Go binary — commonly run on Linux)

## Description

Evilginx2 is a standalone reverse proxy: instead of cloning a login page, it
transparently relays the victim's traffic to the genuine site, so the victim
sees the real page and completes a real login — including any OTP/push MFA
prompt. In the process Evilginx harvests the username, password, and, critically,
the resulting **session token**. Replaying that token lets an attacker resume the
authenticated session without re-authenticating, which is why one-time codes and
push approvals don't stop it. In a sanctioned red-team or awareness exercise it
demonstrates, concretely, why "we have MFA" is not the end of the story.

Attacks are driven by *phishlets* (YAML configs describing how to proxy a given
service). Keep engagements reference-level: use test/lab targets and consenting
participants, not live third-party services.

## Installation

```bash
# Build from source (requires Go)
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2 && make

# Run it (needs privileges to bind :53/:80/:443)
sudo ./bin/evilginx -p ./phishlets
```

## Usage examples

Evilginx runs as an interactive console. A typical authorized-lab session:

```text
# Point the tool at the domain you control and its public IP
: config domain example-lab.test
: config ipv4 203.0.113.10

# Enable a phishlet and give it a hostname
: phishlets hostname demo example-lab.test
: phishlets enable demo

# Create a lure (the link handed to consenting test participants)
: lures create demo
: lures get-url 0
```

Captured credentials and session tokens land in the `sessions` view:

```text
# List captured sessions (tokens included)
: sessions
# Inspect one captured session in detail
: sessions 1
```

## The defense: phishing-resistant MFA

Evilginx works because OTP codes and push approvals are **relayable** — the proxy
just forwards them. FIDO2/WebAuthn credentials are not: the browser
cryptographically binds each assertion to the real site's origin, so a proxy on a
look-alike domain cannot produce a valid signature. Hardware
[security keys (YubiKey / FIDO2)](../hardware/security-keys.md) are the practical
countermeasure — this is exactly the "reverse-proxy phishing kit" that page warns
OTP/SMS cannot survive.

## Notes & references

- Use only against infrastructure you own or are explicitly authorized to test;
  proxying a real service's users without consent is illegal.
- Upstream is now maintained as **Evilginx** (v3.x) at
  https://github.com/kgretzky/evilginx — "evilginx2" refers to the older 2.x line.
- Detection cues for defenders: logins from look-alike domains, impossible-travel
  session reuse, and new-device sessions immediately after an auth event.
- Related simulation tooling: [Gophish](gophish.md) for volume click-tracking;
  broader defenses in [Phishing Awareness & Defense](phishing-awareness-defense.md).
- Docs & phishlet format: https://github.com/kgretzky/evilginx2/wiki
