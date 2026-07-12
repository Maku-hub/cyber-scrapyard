# Scout Suite

> Multi-cloud security-auditing tool: pulls a read-only snapshot of your cloud
> account's configuration and produces an offline HTML report of risks.

- **Link:** https://github.com/nccgroup/ScoutSuite
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

Scout Suite (from NCC Group) is a configuration auditor for AWS, Azure, Google
Cloud, Oracle Cloud, and Alibaba Cloud. Using each provider's API with read-only
credentials, it gathers the state of your services — IAM, storage buckets,
security groups, key management, logging — and evaluates it against built-in
rules, then generates a static HTML dashboard highlighting misconfigurations
(public buckets, over-permissive policies, unencrypted resources, missing
logging). Because the report is static, it's easy to share and diff over time,
and nothing is changed in the account.

## Installation

```bash
# Isolate in a virtualenv and install from PyPI
pip install scoutsuite
```

## Usage examples

```bash
# Audit an AWS account using the default credential chain / a named profile
scout aws --profile my-profile

# Restrict to specific regions to speed up large accounts
scout aws --regions eu-west-1,us-east-1

# Audit Azure using the logged-in Azure CLI session
scout azure --cli

# Audit Google Cloud for a specific project with a service-account key
scout gcp --service-account key.json --project-id my-project
```

Open the generated `scoutsuite-report/scoutsuite-results/...html` in a browser.

## Notes & references

- Always use **read-only** credentials (e.g. AWS `SecurityAudit` /
  `ViewOnlyAccess`) — Scout Suite never needs write access.
- Results are colour-coded by severity; use the ruleset filters to focus on
  what matters for your environment.
- Wiki/docs: https://github.com/nccgroup/ScoutSuite/wiki
- Overlaps with [Prowler](prowler.md) — Scout Suite excels at a shareable
  visual posture snapshot; Prowler at granular compliance checks and CI.
