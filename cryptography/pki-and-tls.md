# PKI & TLS

> How the padlock actually works: symmetric vs asymmetric crypto, certificate
> authorities and the chain of trust, X.509 certificates, and what happens
> during a TLS handshake.

- **Link:** https://datatracker.ietf.org/doc/html/rfc8446 (TLS 1.3)
- **Type:** concept reference (not a single tool)
- **Platform:** cross-platform

## Description

This page is a themed reference rather than a tool page. Almost every secure
protocol you meet — HTTPS, SMTPS, VPNs, signed software — rests on the same few
building blocks: two kinds of encryption, a hierarchy of trust (PKI), a
standard certificate format (X.509), and a negotiation ritual (the TLS
handshake). Understanding these explains what [OpenSSL](openssl.md) commands are
really doing and why a cert error means what it does.

## Symmetric vs asymmetric

- **Symmetric** — one shared secret key encrypts *and* decrypts (AES,
  ChaCha20). Fast, ideal for bulk data, but both parties must already share the
  key.
- **Asymmetric** (public-key) — a keypair where the **public** key encrypts (or
  verifies) and the **private** key decrypts (or signs) (RSA, ECDSA, X25519).
  Solves key distribution but is slow.
- **Hybrid** — the real world uses both: asymmetric crypto to agree on a
  throwaway symmetric session key, then symmetric crypto for the actual traffic.
  TLS works exactly this way.

## PKI & certificate authorities

**Public Key Infrastructure (PKI)** is the system of roles and policies that
binds a public key to an identity. A **Certificate Authority (CA)** signs
certificates vouching that "this public key belongs to `example.com`". Trust
flows down a **chain**:

```
Root CA  →  Intermediate CA  →  Leaf (server) certificate
```

Your OS/browser ships a **trust store** of root CAs. A leaf cert is trusted if
it chains up — via valid signatures — to a root you already trust. Break any
link (expired, revoked, wrong hostname, unknown issuer) and validation fails.

## X.509 certificates

An **X.509** certificate is the standard container that binds a public key to a
subject. Key fields:

- **Subject** / **Subject Alternative Names (SAN)** — who the cert is for
  (modern browsers use SAN, not the legacy Common Name).
- **Issuer** — which CA signed it.
- **Validity** — not-before / not-after dates.
- **Public key** — the key being certified.
- **Signature** — the issuer's signature over all of the above.

Inspect one with `openssl x509 -in cert.pem -noout -text` (see [OpenSSL](openssl.md)).

## TLS handshake basics

Simplified TLS 1.3 flow:

1. **ClientHello** — client offers supported TLS versions, cipher suites, and a
   key-share (its ephemeral public key).
2. **ServerHello** — server picks the parameters, sends its key-share and its
   **certificate** (the X.509 chain).
3. **Authentication** — client validates the cert chain against its trust store
   and checks the hostname and validity dates.
4. **Key agreement** — both sides derive the same symmetric session key from the
   exchanged key-shares (ephemeral Diffie–Hellman → forward secrecy).
5. **Encrypted traffic** — everything after is symmetric-encrypted with that
   session key.

## Notes & references

- **Forward secrecy**: ephemeral key exchange means capturing traffic and later
  stealing the server's private key still won't decrypt past sessions.
- Test a server's real-world TLS posture (protocols, ciphers, cert issues,
  known bugs like Heartbleed/ROBOT) with `testssl.sh` in
  [Web Application Security](../web-app-security/), or the quick-and-dirty
  `openssl s_client -connect host:443` (see [OpenSSL](openssl.md)).
- Defenders monitor cert issuance and expiry; see [Defense & Blue Team](../defense-blueteam/)
  for logging/monitoring that catches rogue or expiring certificates.
- TLS 1.3 spec: https://datatracker.ietf.org/doc/html/rfc8446
- Free CA for real certs: Let's Encrypt — https://letsencrypt.org
