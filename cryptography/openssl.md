# OpenSSL

> The crypto swiss-army knife: generate keys and CSRs, inspect and convert
> certificates, hash and encrypt files, and debug a live TLS server — all from
> one CLI.

- **Link:** https://www.openssl.org
- **Type:** open source
- **Platform:** cross-platform

## Description

OpenSSL is both the TLS/crypto library most of the internet is built on and a
sprawling command-line tool. For day-to-day security work it's the fastest way
to mint a keypair, sign a certificate request, look inside an X.509 cert,
convert between PEM/DER/PKCS#12, checksum a file, do quick symmetric
encryption, or connect to a TLS service and read its certificate chain. If you
touch certificates or keys, you end up living in `openssl`.

## Installation

```bash
sudo apt install openssl        # Debian/Kali/Ubuntu (usually preinstalled)
```

## Usage examples

### Keys, CSRs & certificates

```bash
# Generate a 4096-bit RSA private key
openssl genrsa -out private.key 4096

# Generate a modern EC (P-256) private key
openssl ecparam -genkey -name prime256v1 -out ec.key

# Create a Certificate Signing Request (CSR) from an existing key
openssl req -new -key private.key -out request.csr

# Create a self-signed cert (key + cert in one go, valid 365 days)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Inspect a certificate in human-readable form
openssl x509 -in cert.pem -noout -text

# Show just the cert's expiry dates
openssl x509 -in cert.pem -noout -dates

# Convert PEM to DER
openssl x509 -in cert.pem -outform DER -out cert.der

# Bundle key + cert into a PKCS#12 (.pfx) file
openssl pkcs12 -export -inkey key.pem -in cert.pem -out bundle.pfx
```

### Hashing & message digests

```bash
# SHA-256 checksum of a file
openssl dgst -sha256 file.iso

# HMAC-SHA256 with a secret key
openssl dgst -sha256 -hmac "s3cr3t" file.txt
```

### Symmetric encryption / decryption

```bash
# Encrypt a file with AES-256 (prompts for a passphrase; PBKDF2 key derivation)
openssl enc -aes-256-cbc -pbkdf2 -salt -in secret.txt -out secret.enc

# Decrypt it again
openssl enc -d -aes-256-cbc -pbkdf2 -in secret.enc -out secret.txt
```

### Debugging live TLS with s_client

```bash
# Connect to a TLS service and dump its certificate chain
openssl s_client -connect example.com:443 -showcerts

# Force a specific protocol to test what a server accepts
openssl s_client -connect example.com:443 -tls1_2

# Check certificate details straight from a live host
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates
```

## Notes & references

- `-nodes` means "no DES" — i.e. **don't** encrypt the private key with a
  passphrase. Fine for lab/automation, riskier for production keys.
- Prefer `-pbkdf2` (or `-iter`) with `openssl enc`; the legacy key derivation is
  weak. For file encryption you actually want to trust, reach for [age](age.md)
  or [GPG](gpg.md) instead — `openssl enc` lacks authentication by default.
- For a thorough TLS configuration audit (protocols, ciphers, known bugs), use
  `testssl.sh` in [Web Application Security](../web-app-security/) rather than
  hand-rolling `s_client` probes.
- Command docs: https://docs.openssl.org/master/man1/
- See [PKI & TLS](pki-and-tls.md) for the concepts behind these commands and
  [Hashing](hashing.md) for choosing a digest.
