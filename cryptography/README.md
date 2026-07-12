# Cryptography

Tools and concepts for working with keys, certificates, hashes, and encrypted
data. Whether you're minting a certificate, verifying a signed release,
encrypting a file, or figuring out how HTTPS decides to trust a server, the
building blocks live here.

> ⚠️ **Authorized/educational use only.** Encrypt, sign, and inspect only data
> and systems you own or are permitted to work with.

## Tools

| Tool | Summary |
| --- | --- |
| [OpenSSL](openssl.md) | The crypto swiss-army knife — keys, CSRs, certs, hashing, enc/dec, and `s_client` for TLS debugging |
| [GnuPG (GPG)](gpg.md) | OpenPGP implementation — key management, sign/verify, encrypt/decrypt for recipients or by passphrase |
| [age](age.md) | Modern, minimal file encryption with sane defaults (and `rage`, its Rust twin) |

## Concept pages

| Page | Summary |
| --- | --- |
| [PKI & TLS](pki-and-tls.md) | Symmetric vs asymmetric, CAs and the chain of trust, X.509 certs, and the TLS handshake |
| [Hashing](hashing.md) | Hashing vs encryption vs encoding, common algorithms, salting, and HMAC |

## Pick the right tool

- **Certificates & TLS debugging** → [OpenSSL](openssl.md).
- **Signing / verifying releases, OpenPGP ecosystem** → [GPG](gpg.md).
- **Just encrypt a file simply** → [age](age.md).
- **Decode/encode & transform data interactively** (Base64, hex, XOR, JWT,
  cipher recipes) → [CyberChef](../dev-tools/cyberchef.md), the "cyber
  swiss-army knife" for encoding and crypto operations.

## See also

- [Password Cracking & Hashing](../password-cracking/) — identifying and
  cracking the hashes described in [Hashing](hashing.md), e.g. with
  [hashcat](../password-cracking/hashcat.md).
- [Web Application Security](../web-app-security/) — `testssl.sh` for auditing a
  server's TLS configuration in depth.
- [Defense & Blue Team](../defense-blueteam/) — monitoring certificates, keys,
  and encrypted traffic on the defensive side.
- [Developer Tools](../dev-tools/) — including [CyberChef](../dev-tools/cyberchef.md).
