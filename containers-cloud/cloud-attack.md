# Cloud Attack (Pacu & CloudFox)

> Offensive cloud tooling: enumerate a cloud account's attack surface and
> exploit the IAM misconfigurations that lead to privilege escalation and data
> access — the attacker's view of the same accounts the rest of this category
> defends.

- **Type:** open source
- **Platform:** cross-platform (Python / Go CLI)

## Description

Nearly every other page in this category is defensive — scanning images,
benchmarking clusters, auditing account posture. This page is the offensive
counterpart: the tools a red-teamer or penetration tester reaches for *after*
obtaining a set of cloud credentials, to map what those credentials can reach
and to chain misconfigurations into real impact. Two tools cover the workflow:
**CloudFox** for fast, read-only attack-surface enumeration across AWS, Azure,
and GCP, and **Pacu** for actively exploiting an AWS environment through a
modular framework. They pair naturally with the deliberately-vulnerable
[CloudGoat](cloudgoat.md) lab, which spins up scenarios built precisely for this
kind of work.

> ⚠️ These are offensive tools that act on live cloud accounts. Run them only
> against accounts you own or are explicitly authorized to test under a written
> engagement scope. Enumeration and exploitation against third-party accounts is
> illegal. Practise on [CloudGoat](cloudgoat.md) in a throwaway account first.

## CloudFox

Bishop Fox's enumeration tool that answers "what can I do with these
credentials?" — it inventories resources, exposed endpoints, secrets, and
principal permissions, then hands you ready-to-run loot and command files. It is
read-only by design, so it is the safe first step on an engagement.

- **Link:** https://github.com/BishopFox/cloudfox

```bash
# Install via Go, or grab a prebuilt release binary
go install github.com/BishopFox/cloudfox@latest
```

```bash
# Run every AWS enumeration check against a configured profile
cloudfox aws --profile target-profile all-checks

# Find publicly reachable endpoints (the external attack surface)
cloudfox aws --profile target-profile endpoints

# Enumerate IAM principals and what their permissions allow
cloudfox aws --profile target-profile permissions

# Enumerate an Azure subscription instead
cloudfox azure --subscription <sub-id> all-checks

# Enumerate a GCP project
cloudfox gcp --project <project-id> all-checks
```

## Pacu

Rhino Security Labs' AWS exploitation framework — a modular, Metasploit-style
toolkit whose modules perform recon, IAM privilege escalation, persistence,
data exfiltration, and detection evasion against an AWS account.

- **Link:** https://github.com/RhinoSecurityLabs/pacu

```bash
# Install with pipx (isolated) or pip
pipx install pacu
```

```bash
# Launch the interactive framework
pacu
```

```text
# Inside the Pacu prompt — create a session and import AWS keys
set_keys

# List and search the available exploitation modules
ls

# Enumerate the account and permissions of the current credentials
run iam__enum_permissions

# Hunt for viable IAM privilege-escalation paths
run iam__privesc_scan

# Enumerate all resources across the account
run aws__enum_account
```

## Notes & references

- CloudFox is **read-only reconnaissance**; Pacu **changes state** (it can create
  users, policies, and resources). Enumerate with CloudFox first, then use Pacu
  deliberately and clean up anything it creates.
- Both consume the standard AWS credential/profile chain — configure `aws
  configure --profile <name>` before running.
- Workflow: deploy a scenario with [CloudGoat](cloudgoat.md), map it with
  CloudFox, exploit the path with Pacu, then confirm what a defender would have
  seen with [Prowler](prowler.md) and [Scout Suite](scoutsuite.md).
- Pacu module list & docs: https://github.com/RhinoSecurityLabs/pacu/wiki ;
  CloudFox docs: https://github.com/BishopFox/cloudfox
