# crunch

> A pattern-based wordlist generator: give it a length range and a character set
> (or a template), and it emits every matching candidate — for when a targeted,
> rules-driven wordlist beats a generic dump.

- **Link:** https://github.com/crunchsec/crunch
- **Type:** open source
- **Platform:** Linux (ships on Kali)

## Description

Where [CeWL](wordlists.md) scrapes real words off a target's website, **crunch**
generates candidates *combinatorially* from rules you define — useful when you
know the shape of a password (a company Wi-Fi key that's "8 digits", a policy of
"word + 2 digits + symbol", a known prefix). It can stream directly into
[hashcat](hashcat.md) / [John](john-the-ripper.md) or write to a file, and warns
you up front how large the output will be.

Because generated lists explode fast, crunch is best for *narrow, known*
patterns. For unconstrained brute force, prefer hashcat mask attacks (`-a 3`),
which do the same thing on the GPU without writing terabytes to disk.

## Installation

```bash
sudo apt install crunch          # Debian/Kali/Ubuntu
```

## Usage examples

```bash
# Every lowercase string of length 4 to 6 (min max charset)
crunch 4 6 abcdefghijklmnopqrstuvwxyz -o wordlist.txt

# All 8-digit numeric combos — e.g. default routers / PINs
crunch 8 8 0123456789 -o pins.txt
```

```bash
# Pattern with -t: fixed prefix "Pass" + 2 lowercase + 2 digits
#   @ = lowercase, , = uppercase, % = digit, ^ = symbol
crunch 8 8 -t Pass@@%% -o candidates.txt

# Stream straight into hashcat instead of writing a huge file to disk
crunch 8 8 0123456789 | hashcat -m 0 hash.txt
```

## Notes & references

- **Placeholders for `-t`:** `@` lowercase, `,` uppercase, `%` numbers, `^`
  symbols. Escape a literal `@,%^` with `\`.
- crunch prints the total size before generating — a full 8-char mixed-charset
  run is terabytes, so constrain length/charset or pipe instead of `-o`.
- Split massive output with `-b` (bytes) or `-c` (lines per file), e.g.
  `-b 4GB -o START`.
- **Prefer masks for pure brute force:** hashcat `-a 3 ?d?d?d?d?d?d?d?d`
  achieves the same 8-digit space GPU-side with no disk cost — reach for crunch
  when you need an actual file or a pattern hashcat masks can't express.
- Complements [CeWL](wordlists.md) (real words from the target) — combine a CeWL
  list with crunch-generated suffixes for realistic policy-shaped candidates.
