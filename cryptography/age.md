# age

> Modern, dead-simple file encryption: one small tool, sane defaults, no
> config, no ciphersuite choices to get wrong — a friendlier alternative to GPG
> for encrypting files.

- **Link:** https://github.com/FiloSottile/age
- **Type:** open source
- **Platform:** cross-platform

## Description

`age` ("aghe", like the Italian for "ages") is a modern encryption tool built
around a single, opinionated format. Where GPG exposes decades of options, age
gives you exactly one modern scheme (X25519 + ChaCha20-Poly1305) and two ways to
encrypt: to a recipient's public key, or with a passphrase. Keys are short
strings you can paste anywhere, and — usefully — it can encrypt directly to an
SSH key you already have. Great for backups, secrets in Git, and sending files.

## Installation

```bash
sudo apt install age            # Debian/Kali/Ubuntu

# Or via Go
go install filippo.io/age/cmd/...@latest
```

## Usage examples

### Key-pair encryption

```bash
# Generate a keypair (writes the secret key; prints the public key)
age-keygen -o key.txt

# Encrypt a file to a recipient's public key
age -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p -o secret.age secret.txt

# Decrypt with your identity (secret key) file
age -d -i key.txt -o secret.txt secret.age
```

### Passphrase encryption

```bash
# Encrypt with a passphrase instead of keys
age -p -o secret.age secret.txt

# Decrypt (prompts for the passphrase)
age -d -o secret.txt secret.age
```

### Encrypt to an existing SSH key

```bash
# Encrypt to someone's SSH public key (no age key needed)
age -R ~/.ssh/id_ed25519.pub -o secret.age secret.txt

# Decrypt using the matching SSH private key
age -d -i ~/.ssh/id_ed25519 -o secret.txt secret.age
```

## Notes & references

- **rage** is a Rust reimplementation of the same format —
  https://github.com/str4d/rage — fully interoperable (`rage`/`rage-keygen`),
  handy where a static binary or a `pinentry` GUI prompt is preferred.
- Encrypt a directory by piping through tar:
  `tar cz mydir | age -p > mydir.tar.gz.age`.
- age does **not** sign — it only encrypts. For authorship/integrity signatures
  use [GPG](gpg.md) (or `ssh-keygen -Y sign`).
- Spec & format: https://age-encryption.org/v1
- See [PKI & TLS](pki-and-tls.md) for the asymmetric-crypto concepts age builds on.
