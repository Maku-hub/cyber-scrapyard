# Password Cracking & Hashing

Tools for recovering passwords — both **offline** (hashing candidates and
comparing them to a stolen hash) and **online** (guessing against a live login
service) — plus the wordlists that feed them. Use these to demonstrate weak
passwords, crack captured [Wi-Fi handshakes](../wifi-wireless/), and audit
credential hygiene.

> ⚠️ **Authorized use only.** Crack only hashes and accounts you own or are
> explicitly permitted to test.

## Tools

| Tool | Summary |
| --- | --- |
| [Hashcat](hashcat.md) | The fastest cracker — GPU-accelerated, hundreds of hash modes, rule/mask/hybrid attacks |
| [John the Ripper](john-the-ripper.md) | Veteran CPU cracker with auto hash detection and the `*2john` format extractors |
| [Hydra](hydra.md) | Online/network login brute-forcer for SSH, RDP, HTTP forms, and dozens more protocols |
| [Hash identification](hash-identification.md) | hashID & Name-That-Hash — identify a hash type and pick the right hashcat `-m` mode |
| [Wordlists](wordlists.md) | Where to get SecLists, rockyou, and Openwall lists, and build custom ones with CeWL |
| [crunch](crunch.md) | Pattern-based wordlist generator for narrow, known password shapes — complements CeWL |

## Offline vs online

- **Offline** — you already have the hash (a dump, a captured handshake, a
  `*2john` extraction). Speed is everything, so this is where GPUs shine:
  [hashcat](hashcat.md) for raw throughput, [John](john-the-ripper.md) for
  convenience and format extraction. No traffic reaches the target.
- **Online** — no hash, so you attempt real logins against a live service with
  [Hydra](hydra.md). Noisy, slower, and trips lockouts/IDS — but sometimes the
  only option.

## Typical offline workflow

1. **Get the hash** — dump it, capture it, or extract it (`zip2john`,
   `ssh2john`, `hcxpcapngtool`, ...).
2. **Identify the type** — match it against
   https://hashcat.net/wiki/doku.php?id=example_hashes to pick hashcat's `-m`.
3. **First pass** — [rockyou](wordlists.md) straight, then with rules
   (`best64`).
4. **Escalate** — bigger [wordlists](wordlists.md), custom CeWL lists, then mask
   / brute force for short passwords.

See also: [Wi-Fi & Wireless](../wifi-wireless/) for capturing handshakes/PMKIDs
to crack, [Active Directory](../active-directory/) for dumping NTLM/Kerberos
hashes, and [Web Application Security](../web-app-security/) which reuses the
same wordlists for fuzzing.
