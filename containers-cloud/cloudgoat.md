# CloudGoat

> Rhino Security Labs' "vulnerable by design" AWS deployment tool — spins up
> deliberately insecure scenarios so you can practise cloud attack and defence
> safely.

- **Link:** https://github.com/RhinoSecurityLabs/cloudgoat
- **Type:** open source
- **Platform:** cross-platform (Python + Terraform; targets AWS)

## Description

CloudGoat is a training lab, not a scanner. It uses Terraform to deploy
self-contained, intentionally-vulnerable AWS environments — each a named
"scenario" built around a realistic attack path (IAM privilege escalation via a
misconfigured policy, an SSRF leading to credential theft, exposed Lambda
secrets, and so on). You attack the scenario to reach its goal, learning how
real cloud misconfigurations chain together, then tear it all down with one
command. It's the cloud equivalent of a deliberately-vulnerable web app, and a
great way to *understand* the findings that tools like [Prowler](prowler.md) and
[Scout Suite](scoutsuite.md) report.

> Deploy CloudGoat only in a dedicated, non-production AWS account you own. It
> creates deliberately insecure resources — never run it where it could be
> reached by anyone else or left running.

## Installation

```bash
# Clone and install dependencies (requires the AWS CLI and Terraform installed)
git clone https://github.com/RhinoSecurityLabs/cloudgoat.git
cd cloudgoat
pip install -r ./requirements.txt
```

## Usage examples

```bash
# One-time config (sets your whitelisted source IP, etc.)
./cloudgoat.py config whitelist --auto

# List the available vulnerable scenarios
./cloudgoat.py list all

# Deploy a scenario (creates AWS resources via Terraform)
./cloudgoat.py create iam_privesc_by_rotation

# Destroy the scenario and all resources it created
./cloudgoat.py destroy iam_privesc_by_rotation
```

## Notes & references

- Always `destroy` a scenario when finished — leftover insecure resources cost
  money and are a real risk.
- Each scenario ships with a README describing the start credentials and goal;
  work the path, then confirm what a scanner would have flagged.
- Scenario write-ups and background: https://rhinosecuritylabs.com/
- Use alongside [Prowler](prowler.md) / [Scout Suite](scoutsuite.md) to see the
  same misconfigurations from the defender's side.
