# Hashcat

> The world's fastest password recovery tool — GPU-accelerated cracking of
> hundreds of hash types with dictionary, rule, mask, and hybrid attacks.

- **Link:** https://github.com/hashcat/hashcat
- **Type:** open source
- **Platform:** cross-platform (Linux, Windows, macOS)

## Description

Hashcat cracks password hashes offline by hashing candidate passwords and
comparing them to a target. Its edge is speed: it runs on GPUs and can try
billions of candidates per second on modern hardware. You tell it *what* the
hash is with a **mode** (`-m`), *how* to generate candidates with an **attack
mode** (`-a`), and feed it wordlists, rules, or masks. It's the go-to for
cracking captured [Wi-Fi handshakes](../wifi-wireless/hcxtools.md), dumped
credential databases, NTLM hashes from Active Directory, and archive/document
hashes extracted with `*2john`-style tools.

## Installation

```bash
sudo apt install hashcat        # Debian/Kali/Ubuntu

# Verify your GPU/OpenCL is detected
hashcat -I
```

## Usage examples

### Hash modes and attack modes

```bash
# -m = hash type, -a = attack mode. Common attack modes:
#   -a 0 straight (wordlist)   -a 1 combinator
#   -a 3 mask (brute force)    -a 6/7 hybrid wordlist+mask
```

### Dictionary and rules

```bash
# Straight dictionary attack on MD5 hashes (-m 0)
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules: mutate each word (best64 is the classic ruleset)
hashcat -m 0 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# NTLM hashes (-m 1000) from an AD dump
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r rules/best64.rule
```

### Mask / brute force

```bash
# Mask attack: 6 lowercase letters then 2 digits (?l lower, ?d digit, ?u upper, ?s symbol)
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?l?l?d?d

# Hybrid: wordlist words with 3 digits appended
hashcat -m 0 -a 6 hashes.txt rockyou.txt ?d?d?d
```

### Cracking a Wi-Fi handshake / PMKID

```bash
# WPA-PBKDF2-PMKID+EAPOL (from hcxpcapngtool) — the unified WPA mode
hashcat -m 22000 -a 0 hashes.hc22000 rockyou.txt
```

### Managing sessions and results

```bash
# Show already-cracked results for a hash file
hashcat -m 0 hashes.txt --show

# Named, resumable session
hashcat -m 0 -a 0 hashes.txt rockyou.txt --session job1
hashcat --session job1 --restore
```

## Notes & references

- **Finding the right `-m`:** the mode number is the hard part. Match your hash
  against the official reference:
  https://hashcat.net/wiki/doku.php?id=example_hashes
- Cracked passwords are appended to `hashcat.potfile`; `--show` reads from it.
- Benchmark your hardware with `hashcat -b`.
- Extract hashes from files/archives with the `*2john` tools shipped with
  [John the Ripper](john-the-ripper.md) — the output is often hashcat-compatible.
- Feed it good [wordlists](wordlists.md) and rules; for online/network login
  brute force instead of offline hashes, use [Hydra](hydra.md).
- Cracking NTLM/Kerberos hashes dumped from a domain? See
  [Active Directory](../active-directory/) for how to obtain them.
- Docs: https://hashcat.net/wiki/
