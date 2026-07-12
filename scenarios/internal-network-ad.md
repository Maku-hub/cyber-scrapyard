# Internal Network & Active Directory

> You have a foothold on a corporate LAN (a low-privilege host or a network
> drop). Enumerate the environment and work methodically toward Domain Admin in
> an **authorized internal penetration test**.

## Scope & assumptions

- **Authorized use only.** Internal AD attacks are noisy and high-impact.
  Operate strictly within the rules of engagement: agreed subnets, no disruption
  of production, and a clear escalation contact. Poisoning and coercion attacks
  can affect bystander systems — confirm they're permitted and time-boxed.
- You start with L2/L3 access to a corporate subnet and, optionally, a
  low-privilege domain or local account.
- Goal: demonstrate a realistic path to Domain Admin (or equivalent) and
  document every step for remediation.

## Phase 1 — Host & port discovery

Establish what's on the subnet: live hosts, open ports, and — critically — the
Domain Controllers (LDAP/Kerberos/SMB, ports 88/389/445).

- Sweep large ranges fast with [Masscan](../recon-scanning/masscan.md), then
  fingerprint services in detail with [Nmap](../recon-scanning/nmap.md). See the
  [recon methodology](../methodology/recon-methodology.md) for the masscan→nmap
  hand-off.

```bash
masscan -p88,389,445,3389,5985 10.0.0.0/16 --rate=2000 -Pn   # find DCs & mgmt ports fast
nmap -sV -p88,389,445 10.0.0.10                              # confirm a DC
```

## Phase 2 — Passive listening & poisoning

Before touching accounts, listen. Broadcast protocols (LLMNR/NBT-NS/mDNS) and
IPv6 autoconfiguration leak authentication you can capture.

- Poison name-resolution with [Responder](../active-directory/responder.md) to
  capture NetNTLM hashes.
- Abuse default IPv6 with [mitm6](../active-directory/mitm6.md) to become the
  network's DNS and relay DHCPv6 clients.

```bash
responder -I eth0 -wv           # answer LLMNR/NBT-NS, capture NetNTLMv2
mitm6 -d example.corp           # IPv6 DNS takeover for the domain
```

## Phase 3 — Capture & relay credentials

Turn captured/coerced authentication into access. Force a target to
authenticate, then relay it to a host that lacks SMB signing (or crack it
offline).

- Trigger authentication from privileged machines with
  [coercion tools](../active-directory/coercion-tools.md).
- Relay and operate credentials/hashes across the domain with
  [Impacket](../active-directory/impacket.md) (e.g. `ntlmrelayx`) and validate
  access broadly with [NetExec](../active-directory/netexec.md).

```bash
# Relay coerced auth to unsigned SMB, dumping local SAM on success
ntlmrelayx.py -tf targets.txt -smb2support
# Spray a captured hash across the subnet to see where it's local admin
netexec smb 10.0.0.0/24 -u svc_backup -H <NTLM> --local-auth
```

## Phase 4 — Enumerate AD & find attack paths

With any valid domain credential, map the directory and let the graph reveal the
shortest path to Domain Admin (ACL abuse, sessions, delegations).

- Collect and analyse the domain graph with [BloodHound](../active-directory/bloodhound.md).
  Cross-reference tooling and technique depth in the
  [Active Directory](../active-directory/) category.

```bash
# Collect graph data with a domain user (via NetExec's BloodHound module or a collector)
netexec ldap 10.0.0.10 -u user -p 'Passw0rd' --bloodhound --collection All
```

## Phase 5 — Crack & Kerberoast

Use the graph to prioritise credential attacks: request service tickets for
accounts with SPNs (Kerberoasting) and AS-REP-roast accounts without preauth,
then crack them offline.

- Perform the ticket attacks described in
  [Kerberos attacks](../active-directory/kerberos-attacks.md) (Impacket's
  `GetUserSPNs`/`GetNPUsers`).
- Crack the resulting hashes with [Hashcat](../password-cracking/hashcat.md).

```bash
GetUserSPNs.py example.corp/user:'Passw0rd' -dc-ip 10.0.0.10 -request
hashcat -m 13100 kerb.hash rockyou.txt        # crack TGS-REP (Kerberoast)
```

## Phase 6 — Lateral movement & pivot

Move to the hosts BloodHound flagged, harvest more credentials, and pivot deeper
into segmented networks.

- Get interactive access to Windows hosts via WinRM with
  [Evil-WinRM](../active-directory/evil-winrm.md), and execute across many hosts
  with [NetExec](../active-directory/netexec.md).
- Dump secrets in memory/LSASS with [Mimikatz](../post-exploitation/mimikatz.md).
- Reach unrouted subnets by [pivoting & tunneling](../post-exploitation/pivoting-tunneling.md).

```bash
evil-winrm -i 10.0.0.25 -u admin -H <NTLM>    # WinRM shell with pass-the-hash
# On the host: sekurlsa::logonpasswords  (Mimikatz) to harvest cached creds
```

## Phase 7 — Escalate to Domain Admin

Chain the collected privileges — an ACL edit, a DCSync right, or admin on a DC —
into full domain compromise.

- Perform DCSync / replicate secrets with [Impacket](../active-directory/impacket.md)
  (`secretsdump.py`) or [Mimikatz](../post-exploitation/mimikatz.md) once you
  hold the required rights, extracting the `krbtgt` hash to prove impact
  (Golden Ticket) — without persisting beyond the test.

```bash
# With DCSync rights, replicate the KRBTGT / domain hashes as proof of DA
secretsdump.py example.corp/admin@10.0.0.10 -just-dc-user krbtgt
```

## Reporting / next steps

Document the full kill chain: initial access → each pivot → the specific
misconfiguration that enabled escalation (unsigned SMB, LLMNR, roastable SPNs,
dangerous ACLs). Prioritise remediation by which single fix breaks the most
BloodHound paths. Clean up all artifacts (dropped tools, created accounts,
tickets) and hand back any credentials. See the
[Active Directory](../active-directory/) and [Methodology](../methodology/)
categories for defensive mappings and deeper technique references.
