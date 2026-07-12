# Hash Identification (hashID & Name-That-Hash)

> Before you can crack a hash you have to know *what* it is. These tools inspect
> a hash string and suggest its type — and, crucially, the matching hashcat
> `-m` mode — so your attack targets the right algorithm.

- **Link:** hashID https://github.com/psypanda/hashID · Name-That-Hash https://github.com/HashPals/Name-That-Hash
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

Picking the wrong algorithm wastes an entire cracking run. Both tools pattern-
match a hash (length, prefix, character set, and known `$id$` markers) against a
database of formats and rank the likely candidates:

- **hashID** — the long-standing identifier; detects 200+ hash types and can
  print the corresponding [hashcat](hashcat.md) (`-m`) and John (`--format`)
  references with `-m`/`-j`.
- **Name-That-Hash** — a modern rewrite with colorized, confidence-ranked
  output and short summaries that flag which hashes are fast vs. slow to crack.
  Reads from stdin, files, or a single argument.

Identification is a *hint*, not proof — many formats share the same shape (a bare
32-hex string could be MD5, NTLM, or a dozen others), so use context (where you
dumped it from) to disambiguate.

## Installation

```bash
# hashID — via pip or your package manager
pipx install hashid              # or: sudo apt install hashid

# Name-That-Hash — via pip
pipx install name-that-hash      # provides the `nth` command
```

## Usage examples

### hashID

```bash
# Identify a single hash and show the hashcat -m / John --format references
hashid -mj '$1$Etg2ExUZ$F9NTP7uzL9YFn0MpvKlhz0'

# Identify every hash in a file, one per line
hashid -mj hashes.txt
```

### Name-That-Hash

```bash
# Identify one hash passed as an argument
nth -t '5f4dcc3b5aa765d61d8327deb882cf99'

# Read hashes from a file, and show only the most likely results
nth -f hashes.txt --accessible
```

## Notes & references

- **Then crack it:** take the suggested mode straight into
  [hashcat](hashcat.md), e.g. NTLM → `hashcat -m 1000`, bcrypt (`$2b$`) →
  `hashcat -m 3200`, sha512crypt (`$6$`) → `hashcat -m 1800`.
- **Cross-check** against hashcat's example-hashes table when unsure:
  https://hashcat.net/wiki/doku.php?id=example_hashes — matching your hash's
  shape to a known example is the definitive way to confirm `-m`.
- Prefixed formats are unambiguous: `$1$` md5crypt, `$5$` sha256crypt, `$6$`
  sha512crypt, `$2a$/$2b$/$2y$` bcrypt, `$y$` yescrypt, `$krb5tgs$` Kerberos.
- For [John the Ripper](john-the-ripper.md), John's own auto-detection often
  suffices, but these tools still help choose the right `--format=` explicitly.
