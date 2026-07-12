# PingCastle

> The de-facto Active Directory security-audit and health-check tool: it scores
> your domain against a catalogue of known weaknesses and produces a shareable
> HTML risk report — the quickest way to get a defensible "how bad is our AD"
> baseline.

- **Link:** https://github.com/netwrix/pingcastle
- **Type:** source-available — **Non-Profit OSL 3.0**; free to audit your *own*
  organisation internally, but a **commercial licence is required** for
  consultants auditing third parties (see Notes)
- **Platform:** Windows (.NET; runs from any domain-joined workstation)

## Description

PingCastle takes a defender/auditor's view of Active Directory rather than an
attacker's. Pointed at a domain, it collects configuration and object data over
standard protocols and grades the environment against a large ruleset covering
stale objects, weak/legacy protocols, privileged-account hygiene, trust
relationships, delegation, and known privilege-escalation conditions. The output
is a self-contained HTML report with an overall risk score (0 = best) and a
prioritised list of findings with remediation guidance — ideal for establishing
a baseline, tracking hardening over time, and briefing management. It is fast,
read-only in normal use, and needs only an unprivileged domain account, which is
why it is so widely run in the first hour of an AD assessment.

## Installation

```powershell
# Download the prebuilt release ZIP from GitHub and unzip (no install needed):
#   https://github.com/netwrix/pingcastle/releases
# Then run PingCastle.exe from the extracted folder
.\PingCastle.exe
```

## Usage examples

```powershell
# Interactive menu — pick "healthcheck" against the current domain
.\PingCastle.exe

# Non-interactive health check of a specific domain -> generates HTML + XML report
.\PingCastle.exe --healthcheck --server contoso.local

# Health-check every domain reachable via trusts, following them automatically
.\PingCastle.exe --healthcheck --explore-trust

# Map trust relationships across the forest into a consolidated report
.\PingCastle.exe --scanner nullsession --server contoso.local
```

## Notes & references

- **Licensing — read before use on a paid engagement.** PingCastle is released
  under the **Non-Profit Open Software License 3.0**. That permits **free
  internal use** — auditing an AD environment your organisation *owns*. Using it
  as part of **paid/consulting work to audit a third party's** environment
  requires a **commercial (Basic/Pro) licence** from Netwrix. Confirm the current
  terms before billing a client: https://github.com/netwrix/pingcastle and
  https://www.pingcastle.com/
- The score is a *relative* health indicator, not a pass/fail — use it to
  prioritise remediation and to trend improvement over repeat runs.
- Complements the offensive AD tooling here: PingCastle tells the blue team
  *what to fix*, while [BloodHound](bloodhound.md) shows the concrete attack
  paths those weaknesses enable.
- Documentation and rule descriptions:
  https://www.pingcastle.com/documentation/
