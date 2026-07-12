# GnuPG (GPG)

> The standard OpenPGP implementation: manage keypairs, sign and verify files,
> and encrypt/decrypt data for specific recipients or with a passphrase.

- **Link:** https://gnupg.org
- **Type:** open source
- **Platform:** cross-platform

## Description

GnuPG (`gpg`) is the free implementation of the OpenPGP standard. It's how you
verify that a downloaded release really came from its maintainer, encrypt a file
so only a chosen recipient can open it, and sign messages to prove authorship.
It uses public-key cryptography plus a web-of-trust model, and its detached
signatures (`.asc`/`.sig`) are ubiquitous across open-source distribution.

## Installation

```bash
sudo apt install gnupg          # Debian/Kali/Ubuntu
```

## Usage examples

### Key management

```bash
# Generate a new keypair (interactive; pick ECC or RSA 4096)
gpg --full-generate-key

# List your public and secret keys
gpg --list-keys
gpg --list-secret-keys

# Export your public key to share it
gpg --armor --export you@example.com > mypubkey.asc

# Import someone else's public key
gpg --import their-key.asc

# Fetch a key from a keyserver by fingerprint
gpg --keyserver hkps://keys.openpgp.org --recv-keys 0xDEADBEEF
```

### Sign & verify

```bash
# Create a detached signature for a file
gpg --detach-sign --armor release.tar.gz

# Verify a detached signature against its file
gpg --verify release.tar.gz.asc release.tar.gz

# Clear-sign a text message (signature wraps readable text)
gpg --clearsign message.txt
```

### Encrypt & decrypt

```bash
# Encrypt a file for a specific recipient (public-key)
gpg --encrypt --recipient them@example.com secret.txt

# Symmetric encryption with just a passphrase (no keys needed)
gpg --symmetric --cipher-algo AES256 secret.txt

# Decrypt any .gpg file (uses your secret key or prompts for passphrase)
gpg --decrypt secret.txt.gpg > secret.txt
```

## Notes & references

- Always verify a key's **fingerprint** out-of-band before trusting it —
  importing a key does not make it authentic. `gpg --fingerprint <keyid>`.
- Encrypted/signed output is binary by default; add `--armor` (`-a`) for
  ASCII-armored `.asc` you can paste into email.
- For simple, modern file encryption without key-management overhead, [age](age.md)
  is often the better fit; GPG shines for signing and for the existing OpenPGP
  ecosystem.
- User guide: https://www.gnupg.org/documentation/manuals/gnupg/
- Concepts behind the keys: [PKI & TLS](pki-and-tls.md).
