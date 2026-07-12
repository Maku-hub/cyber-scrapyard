# Wordlists & Custom List Generation

> Cracking is only as good as your candidate list. This is where to get proven
> wordlists — SecLists, rockyou, Openwall — and how to build targeted ones with
> CeWL.

- **Link:** SecLists https://github.com/danielmiessler/SecLists · CeWL https://github.com/digininja/CeWL
- **Type:** open source
- **Platform:** cross-platform

## Description

A wordlist is the dictionary a cracker or brute-forcer draws candidates from —
[hashcat](hashcat.md), [John](john-the-ripper.md), [Hydra](hydra.md), and
[Aircrack-ng](../wifi-wireless/aircrack-ng.md) all consume them. General-purpose
lists (leaked passwords, common defaults) crack the low-hanging fruit; a
**custom** list built from words on the target's own website often catches the
rest. The workhorses below cover both cases.

## Installation

```bash
# SecLists — the big collection of security lists (also on Kali by default)
sudo apt install seclists                 # installs under /usr/share/seclists
# or clone it:
git clone https://github.com/danielmiessler/SecLists.git

# rockyou — the classic leaked-password list (ships gzipped on Kali)
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# CeWL — custom wordlist generator (Ruby)
sudo apt install cewl
```

## Usage examples

### Grab a single SecLists file

```bash
# Download one specific list without cloning the whole repo (e.g. DNS names)
wget https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/dns-Jhaddix.txt
```

### Openwall language-specific lists

```bash
# Openwall hosts curated per-language lists — useful for local passphrases
wget https://www.openwall.com/wordlists/     # browse, download, then:
gzip -d mylist.gz
```

### CeWL — spider a site into a custom wordlist

```bash
# Crawl the target site to depth 2, keep words >= 6 chars, save to a file
cewl -d 2 -m 6 -w custom.txt https://example.com

# Also collect email addresses and file metadata while spidering
cewl -d 2 -m 6 -e --meta -w custom.txt https://example.com
```

## Notes & references

- **Where they live on Kali:** `/usr/share/wordlists/` (rockyou, dirb, etc.) and
  `/usr/share/seclists/` (Passwords, Usernames, Discovery, Fuzzing, ...).
- **rockyou** (~14M passwords from a real breach) is the default first pass for
  password hashes and Wi-Fi handshakes.
- **SecLists** is broader than passwords — usernames, fuzzing payloads, and
  directory/DNS discovery lists feed web tools too (see
  [Web Application Security](../web-app-security/)).
- **CeWL + rules:** a small site-specific list run through hashcat/John
  mangling rules often beats a giant generic list. Feed `custom.txt` to
  [hashcat](hashcat.md) `-r` or [John](john-the-ripper.md) `--rules`.
- **Openwall** hosts per-language lists — handy when the target's passwords are
  likely in a specific language: https://www.openwall.com/wordlists/
- Extend and mangle lists with `hashcat-utils`, `rli`, and `maskprocessor`.
