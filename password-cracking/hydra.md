# Hydra (THC-Hydra)

> A fast, protocol-aware **online** brute-forcer: it throws username/password
> guesses at live network services (SSH, FTP, RDP, HTTP forms, and dozens more).

- **Link:** https://github.com/vanhauser-thc/thc-hydra
- **Type:** open source
- **Platform:** cross-platform (Linux, Windows, macOS)

## Description

Unlike [hashcat](hashcat.md) and [John](john-the-ripper.md), which crack hashes
*offline*, Hydra attacks *live* services by actually attempting to log in over
the network. It supports a huge list of protocols — SSH, FTP, Telnet, SMB, RDP,
MySQL/MSSQL/Postgres, SMTP/IMAP/POP3, VNC, and HTTP(S) basic/form auth among
them — and parallelises the attempts. Because it generates real login traffic
it's noisy, triggers lockouts, and is easy to detect, so it suits weak-password
audits and CTFs rather than stealth.

## Installation

```bash
sudo apt install hydra        # Debian/Kali/Ubuntu
```

## Usage examples

```bash
# SSH: single user, wordlist of passwords
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.5

# FTP: lists for both usernames and passwords
hydra -L users.txt -P passwords.txt ftp://10.0.0.5

# RDP with more parallel tasks (-t)
hydra -l administrator -P passwords.txt -t 4 rdp://10.0.0.5

# HTTP POST login form — specify path:params:failure-string (F=)
hydra -l admin -P passwords.txt 10.0.0.5 \
  http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"

# Stop at the first valid pair (-f) and be verbose (-V)
hydra -l admin -P passwords.txt -f -V ssh://10.0.0.5
```

## Notes & references

- Key flags: `-l`/`-L` single/list of users, `-p`/`-P` single/list of passwords,
  `-t` parallel tasks, `-f` stop on first hit, `-s` custom port, `-V` verbose.
- For HTTP form modules, capture the real request (Burp/DevTools) to get the
  exact path, parameters, and failure string right.
- **Watch for account lockout and rate limiting** — online brute force can lock
  users out and will show up in logs/IDS. Tune `-t` and consider
  `-W`/`-w` delays.
- Alternatives worth knowing: `medusa`, `ncrack`, and `patator`.
- Offline hash cracking is a different job — see [hashcat](hashcat.md) and
  [John the Ripper](john-the-ripper.md). Reuse the same [wordlists](wordlists.md).
