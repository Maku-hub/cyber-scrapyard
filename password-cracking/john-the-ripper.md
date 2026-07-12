# John the Ripper

> The veteran password cracker: auto-detects hash types, ships a huge collection
> of format converters, and cracks well on CPU (with GPU support in the jumbo
> build).

- **Link:** https://github.com/openwall/john
- **Type:** open source
- **Platform:** cross-platform (Linux, Windows, macOS)

## Description

John the Ripper (JtR) is the classic offline cracker. Its strengths are
convenience and breadth: point it at a hash file and it *auto-detects* the
format, applies smart default rules, and gets to work. The community **"jumbo"**
build (`john-jumbo`) adds hundreds of formats plus the invaluable `*2john`
utilities that extract crackable hashes from ZIP/RAR archives, PDFs, KeePass
databases, SSH keys, and more. Reach for JtR for quick CPU cracking and format
extraction; switch to [hashcat](hashcat.md) when you need raw GPU throughput.

## Installation

```bash
sudo apt install john        # Debian/Kali/Ubuntu (jumbo build)
```

## Usage examples

### Basic cracking

```bash
# Auto-detect format and crack with default wordlist + rules
john hashes.txt

# Use a specific wordlist and mangling rules
john --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes.txt

# Force a format when auto-detect guesses wrong
john --format=nt hashes.txt

# Incremental (brute-force) mode when the wordlist is exhausted
john --incremental hashes.txt

# Show cracked passwords
john --show hashes.txt
```

### Cracking Linux logins

```bash
# Combine /etc/passwd and /etc/shadow into one file, then crack
unshadow /etc/passwd /etc/shadow > creds.txt
john creds.txt
```

### Extracting hashes from files (the *2john tools)

```bash
# Pull a crackable hash out of a password-protected ZIP, then crack it
zip2john secret.zip > zip.hash
john --wordlist=rockyou.txt zip.hash

# Same pattern for other formats: rar2john, pdf2john, ssh2john, keepass2john ...
ssh2john id_rsa > key.hash
john key.hash
```

## Notes & references

- Cracked results are stored in `~/.john/john.pot`; `--show` reads from it.
- List supported formats with `john --list=formats`; many `*2john` extractors
  live in `/usr/share/john/` or on your `$PATH`.
- The `*2john` output is frequently compatible with
  [hashcat](hashcat.md) too — extract with JtR, crack on GPU with hashcat.
- Pair with strong [wordlists](wordlists.md) and rules for best results.
- Docs: https://www.openwall.com/john/doc/
