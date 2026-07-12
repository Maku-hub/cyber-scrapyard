# Prowler

> Open-source security assessment and compliance tool for AWS, Azure, GCP, and
> Kubernetes — hundreds of granular checks mapped to common frameworks.

- **Link:** https://github.com/prowler-cloud/prowler
- **Type:** open source
- **Platform:** cross-platform (Python; CLI + optional web UI)

## Description

Prowler runs a large library of security checks against your cloud accounts and
reports findings mapped to standards like CIS, PCI DSS, HIPAA, GDPR, NIST, and
the AWS Foundational Security Best Practices. It started as an AWS tool and now
also covers Azure, GCP, and Kubernetes. Compared with a visual posture snapshot,
Prowler leans toward breadth and automation: filter by service, severity,
compliance framework, or individual check, and emit machine-readable output
(CSV/JSON/JSON-OCSF) that plugs into CI, ticketing, or Security Hub.

## Installation

```bash
# Install from PyPI (use a virtualenv)
pip install prowler
```

## Usage examples

```bash
# Full AWS assessment using the default credentials/profile
prowler aws

# Only run a specific compliance framework
prowler aws --compliance cis_2.0_aws

# Focus on one service and only report failures
prowler aws --services s3 --status FAIL

# Filter by severity and write JSON output
prowler aws --severity critical high --output-formats json-ocsf

# Assess Azure / GCP / Kubernetes
prowler azure --az-cli-auth
prowler gcp --project-ids my-project
prowler kubernetes
```

## Notes & references

- Use read-only credentials; on AWS the managed `SecurityAudit` +
  `ViewOnlyAccess` policies cover most checks.
- `prowler <provider> --list-checks` / `--list-compliance` to explore what's
  available before a full run.
- Docs: https://docs.prowler.com/
- Complements [Scout Suite](scoutsuite.md): run both — Prowler for
  compliance-mapped depth, Scout Suite for a shareable visual overview. Practise
  on the intentionally-vulnerable [CloudGoat](cloudgoat.md) lab.
