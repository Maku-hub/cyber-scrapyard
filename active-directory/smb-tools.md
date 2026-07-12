# SMB Tools (smbclient, smbmap, enum4linux-ng)

> Enumerate and interact with Windows/Samba file shares — list shares, check
> your access, browse directories, and pull or push files. Usually the next
> step after a scanner or NetExec flags open SMB on 445.

- **Link:** https://github.com/ShawnDEvans/smbmap · https://github.com/cddmp/enum4linux-ng · https://www.samba.org (smbclient)
- **Type:** open source
- **Platform:** Linux (cross-platform)

## Description

SMB (ports 139/445) is where a lot of AD loot lives: file shares, scripts,
config files, credentials in plaintext. Three tools cover the common needs:

- **smbclient** — an FTP-style interactive client for browsing a single share
  and transferring files.
- **smbmap** — enumerates *all* shares on a host and, crucially, shows your
  READ/WRITE permission on each; can also search file contents and execute
  commands.
- **enum4linux-ng** — a modern rewrite of enum4linux that pulls broad SMB/RPC
  info: users, groups, shares, password policy and OS details, often via null
  sessions.

## Installation

```bash
# smbclient (Samba client) and enum4linux-ng
sudo apt install smbclient enum4linux-ng

# smbmap
pipx install smbmap
```

## Usage examples

### smbmap — enumerate shares and permissions

```bash
# List shares and your access with credentials
smbmap -H 10.0.0.5 -u jsmith -p 'Passw0rd!'

# Try a null/guest session (no credentials)
smbmap -H 10.0.0.5 -u '' -p ''

# Recursively list files in a share, then search for interesting names
smbmap -H 10.0.0.5 -u jsmith -p 'Passw0rd!' -R Share --depth 5
```

### smbclient — browse and transfer

```bash
# List shares on a host (-N = no password / anonymous)
smbclient -L //10.0.0.5 -N

# Connect to a share interactively (then use ls / get / put / mget *)
smbclient //10.0.0.5/Share -U 'corp.local\jsmith'

# Pass-the-hash with smbclient
smbclient //10.0.0.5/Share -U administrator --pw-nt-hash 31d6cfe0d16ae931b73c59d7e0c089c0
```

### enum4linux-ng — broad enumeration

```bash
# Full enumeration (users, groups, shares, policy, OS) via null session
enum4linux-ng -A 10.0.0.5

# Authenticated enumeration
enum4linux-ng -A -u jsmith -p 'Passw0rd!' 10.0.0.5
```

## Notes & references

- For sweeping shares across a whole subnet at once, [NetExec](netexec.md)'s
  `--shares` is faster; use these tools to dig into individual hosts.
- Null-session enumeration often works against legacy/misconfigured DCs and is a
  cheap early win.
- smbmap: https://github.com/ShawnDEvans/smbmap ·
  enum4linux-ng: https://github.com/cddmp/enum4linux-ng
