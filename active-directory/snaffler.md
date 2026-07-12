# Snaffler

> Crawls the SMB shares an account can reach across the whole domain and
> flags files that look like credentials, keys, config secrets or PII — the
> fast way to turn "I have a low-priv user" into "I found a password".

- **Link:** https://github.com/SnaffCon/Snaffler
- **Type:** open source
- **Platform:** Windows (.NET; runs from a domain-joined or domain-reachable host)

## Description

Once you have any domain account, the interesting loot is usually sitting in a
readable file share somewhere — scripts with hard-coded passwords, `web.config`
connection strings, `.kdbx`/`.ppk`/`.pem` keys, unattended-install answer files,
or spreadsheets full of PII. Snaffler automates that hunt: it enumerates hosts
from Active Directory, finds their shares, walks the directory trees, and applies
a large ruleset to grade files and even individual lines by how likely they are
to contain secrets. Instead of manually `smbclient`-ing share after share, you
get a colour-coded, severity-ranked list of the files worth opening. It is a
staple of the enumeration phase on an internal AD engagement.

## Installation

```bash
# Grab a prebuilt binary from the GitHub Releases page (Snaffler.exe)
#   https://github.com/SnaffCon/Snaffler/releases
# ...or build from source with the .NET SDK / Visual Studio
dotnet build Snaffler.sln -c Release
```

## Usage examples

```powershell
# Auto-discover domain hosts/shares and log findings to console + file
Snaffler.exe -s -o snaffler.log

# Loud/verbose: show every share and file considered (noisier, good for debug)
Snaffler.exe -s -v data -o snaffler.log

# Target specific hosts instead of enumerating the whole domain
Snaffler.exe -n host1,host2 -s -o snaffler.log

# Only crawl shares (skip the file-content grading) for a quick share map
Snaffler.exe -s -m share
```

## Notes & references

- Findings are graded **Black / Red / Yellow / Green** (most to least
  interesting); start at the top of the list and work down.
- It is **noisy** — mass share enumeration touches a lot of hosts and generates
  events. On a monitored network expect detection; tune scope with `-n`/`-i`.
- Complements share access with [SMB Tools](smb-tools.md) (`smbclient`,
  `smbmap`, `enum4linux-ng`) once Snaffler points you at a specific share, and
  pairs with [NetExec](netexec.md) for spidering/enumeration at scale
  (`nxc smb <range> -u <user> -p <pass> --spider`).
- Ruleset and options are documented in the project README:
  https://github.com/SnaffCon/Snaffler/blob/master/README.md
