# Hashing

> Three things people constantly confuse — hashing, encryption, and encoding —
> plus the algorithms that matter, why salt exists, and what HMAC adds.

- **Link:** https://en.wikipedia.org/wiki/Cryptographic_hash_function
- **Type:** concept reference (not a single tool)
- **Platform:** cross-platform

## Description

This page is a themed reference rather than a tool page. "It's hashed" gets said
about things that are actually encrypted or merely encoded — and the difference
decides whether data is protected at all. This page pins down the distinctions,
lists the algorithms worth knowing, and explains the defences (salt, HMAC) that
turn a raw hash into something safe to store.

## Hashing vs encryption vs encoding

| Property | Hashing | Encryption | Encoding |
| --- | --- | --- | --- |
| Reversible? | No (one-way) | Yes, with a key | Yes, no key needed |
| Needs a key/secret? | No | Yes | No |
| Purpose | Integrity, fingerprints, password storage | Confidentiality | Format/transport safety |
| Examples | SHA-256, bcrypt | AES, RSA | Base64, hex, URL-encoding |

Key takeaway: **encoding is not security.** Base64 or hex can be decoded by
anyone — it only changes the representation. Encryption protects confidentiality
but requires key management. Hashing is one-way: you can verify a value but not
recover it.

## Common algorithms

- **Broken / legacy** — MD5, SHA-1. Collision-vulnerable; fine only as
  non-security checksums, never for signatures or passwords.
- **General-purpose (fast)** — SHA-256, SHA-512 (SHA-2 family), SHA-3,
  BLAKE2/BLAKE3. Use for file integrity, digital signatures, HMAC.
- **Password hashing (deliberately slow)** — bcrypt, scrypt, **Argon2** (the
  current recommendation), PBKDF2. Slowness plus salting is the whole point:
  it throttles offline cracking.

> Rule: a **fast** hash is the wrong tool for passwords. Fast hashing is exactly
> what makes [hashcat](../password-cracking/hashcat.md) devastating against
> unsalted SHA/MD5 password dumps.

## Salting

A **salt** is a unique random value added to each input before hashing. It means
identical passwords produce different hashes, which:

- defeats precomputed **rainbow tables**, and
- forces an attacker to crack each hash individually rather than all at once.

Salts don't need to be secret — they're stored alongside the hash. A **pepper**
is a related idea: a secret value kept separately (e.g. in app config) and mixed
in, so a database leak alone isn't enough.

## HMAC

**HMAC** (Hash-based Message Authentication Code) combines a hash with a secret
key to prove both **integrity** and **authenticity** — that a message wasn't
tampered with *and* came from someone holding the key. Plain hashes give
integrity only; anyone can recompute them. HMAC is what signs API requests,
webhook payloads, and session tokens.

```bash
# Compute an HMAC-SHA256 over a file with a shared secret (see openssl.md)
openssl dgst -sha256 -hmac "s3cr3t" message.txt
```

## Notes & references

- **Identify an unknown hash** before cracking it: match its length/format
  against https://hashcat.net/wiki/doku.php?id=example_hashes, or use tools like
  `hashid` / `hash-identifier`. See the hash-identification step in
  [Password Cracking & Hashing](../password-cracking/) and then feed the right
  `-m` mode to [hashcat](../password-cracking/hashcat.md).
- Quick checksums locally: `sha256sum file` or `openssl dgst -sha256 file`
  (see [OpenSSL](openssl.md)).
- Decoding/encoding chains (Base64, hex, URL, gzip, XOR) are fastest to unpick
  in [CyberChef](../dev-tools/cyberchef.md).
- Password-storage guidance: OWASP Password Storage Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
