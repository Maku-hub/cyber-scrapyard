# BloodHound

> Graph-based AD attack-path mapping. Collects users, groups, sessions, ACLs
> and trusts, then shows the shortest path from where you are to Domain Admin —
> the standard tool for finding non-obvious privilege-escalation chains.

- **Link:** https://github.com/SpecterOps/BloodHound
- **Type:** open source (Community Edition) / commercial (Enterprise)
- **Platform:** cross-platform (web UI + Neo4j backend; collectors for Windows/Linux)

## Description

BloodHound turns Active Directory into a graph you can query. A **collector**
(SharpHound for Windows, or `bloodhound-python`/nxc for Linux) gathers objects
and relationships — group memberships, active sessions, ACL rights, local-admin
membership, Kerberos delegation, domain trusts — and loads them into a Neo4j
database. The web UI then lets you run prebuilt queries such as "Shortest Path
to Domain Admins" to reveal escalation chains that would take hours to map by
hand. It's the go-to tool for planning lateral movement and privilege
escalation in AD.

## Installation

```bash
# BloodHound Community Edition via the official Docker Compose (easiest)
curl -L https://ghst.ly/getbhce | docker compose -f - up

# Python collector (run from a Linux attacker box with domain creds)
pipx install bloodhound
```

The Windows collector **SharpHound** ships with BloodHound releases:
https://github.com/SpecterOps/SharpHound

## Usage examples

Collect the data first, then import the resulting JSON/ZIP into the UI.

```bash
# Linux collector: gather everything using domain credentials
bloodhound-python -u jsmith -p 'Passw0rd!' -d corp.local -ns 10.0.0.1 -c All

# Collect via NetExec's LDAP module (no separate collector needed)
nxc ldap dc01.corp.local -u jsmith -p 'Passw0rd!' --bloodhound --collection All --dns-server 10.0.0.1
```

```powershell
# Windows collector (SharpHound) — collect all methods, zip the output
.\SharpHound.exe -c All --zipfilename loot

# Stealthier: session/loop collection over time
.\SharpHound.exe -c Session --loop --loopduration 02:00:00
```

Then in the web UI: upload the ZIP, mark your owned principals, and run
built-in queries — e.g. **Shortest Paths → Shortest Path to Domain Admins**, or
Cypher queries to find Kerberoastable users, unconstrained delegation, etc.

## Notes & references

- Node/edge terms: `MemberOf`, `AdminTo`, `HasSession`, `GenericAll`,
  `WriteDacl`, `AllowedToDelegate` — each edge is an abusable relationship with
  guidance shown in the UI ("Abuse Info").
- Mark compromised accounts/computers as **Owned** and high-value targets as
  **High Value** to make paths meaningful.
- Legacy BloodHound (v4, Python Neo4j) still appears in older write-ups; CE is
  the current version.
- Docs: https://bloodhound.specterops.io  ·  Custom queries:
  https://github.com/SpecterOps/BloodHound-Legacy/tree/master/customqueries
