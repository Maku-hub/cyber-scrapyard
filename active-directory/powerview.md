# PowerView

> The go-to PowerShell module for Active Directory enumeration from a
> domain-joined (or domain-reachable) Windows host — users, groups, computers,
> ACLs, trusts, GPOs and sessions, all via LDAP with no extra tooling.

- **Link:** https://github.com/PowerShellMafia/PowerSploit
- **Type:** open source
- **Platform:** Windows (PowerShell / .NET); see PowerView.py for cross-platform

## Description

PowerView is part of the PowerSploit toolkit (`Recon/PowerView.ps1`). It wraps
raw LDAP and Windows API calls in convenient `Get-Domain*` / `Find-*` cmdlets,
so an operator with any domain context can map the environment without dropping
extra binaries: enumerate objects and their attributes, hunt for where users are
logged in, and — most usefully — read the ACLs that reveal delegation and
privilege-escalation paths. It's the manual, surgical counterpart to
[BloodHound](bloodhound.md): BloodHound collects and graphs everything at once,
while PowerView answers a specific question on demand. PowerSploit itself is
archived/no longer maintained, but PowerView remains a reference-standard tool
and the queries carry over to modern reimplementations.

## Installation

```powershell
# Import the module into the current PowerShell session
Import-Module .\PowerView.ps1

# Or dot-source it
. .\PowerView.ps1
```

## Usage examples

```powershell
# Basic domain and current-context information
Get-Domain
Get-DomainController

# Enumerate users, groups and computers
Get-DomainUser -Identity jsmith -Properties samaccountname,description
Get-DomainGroupMember -Identity 'Domain Admins'
Get-DomainComputer -Properties dnshostname,operatingsystem

# Find Kerberoastable (SPN) and AS-REP-roastable accounts
Get-DomainUser -SPN
Get-DomainUser -PreauthNotRequired

# Where does a given user have a session / where am I local admin?
Find-DomainUserLocation -UserIdentity jsmith
Find-LocalAdminAccess

# Read ACLs to spot delegation / escalation rights (resolve GUIDs to names)
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs

# Enumerate domain trusts
Get-DomainTrust
```

## Notes & references

- PowerView.py — a cross-platform Python port that speaks the same query model
  from Linux, no PowerShell needed: https://github.com/aniqfakhrul/powerview.py
- The `dev` branch of PowerSploit historically carried the newest PowerView
  cmdlets; because the repo is archived, many operators pin a known-good copy.
- For automated, graph-based path finding rather than manual queries, use
  [BloodHound](bloodhound.md); for protocol-level enumeration from Linux, see
  [NetExec](netexec.md).
- PowerView cheat sheet (HarmJ0y):
  https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993