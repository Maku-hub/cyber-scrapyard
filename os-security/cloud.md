# Cloud

> A short set of pointers for learning cloud security hands-on. Cloud "OS" is
> really a set of managed services and IAM; the fastest way to understand its
> failure modes is a deliberately vulnerable playground.
>
> ⚠️ **For authorized and educational use only.** Only attack cloud accounts and
> resources you own or are explicitly authorized to test — and mind the cost of
> resources you spin up.

## Learning by doing

- **CloudGoat** — Rhino Security Labs' "vulnerable by design" AWS lab; provisions
  realistic misconfigured scenarios (over-permissive IAM, exposed services,
  privilege-escalation paths) to work through. Full page:
  [../containers-cloud/cloudgoat.md](../containers-cloud/cloudgoat.md).
- **Pawel Rzepa's write-ups** — practical cloud security research and CloudGoat
  walkthroughs. <https://rzepsky.medium.com/>

## Security testing

- **Audit posture** — [Prowler](../containers-cloud/prowler.md) and
  [ScoutSuite](../containers-cloud/scoutsuite.md).
- **Offensive (authorized)** — [Cloud Attack](../containers-cloud/cloud-attack.md)
  (Pacu, CloudFox) practised against a [CloudGoat](../containers-cloud/cloudgoat.md) lab.
- Full category: [Containers & Cloud Security](../containers-cloud/).

## Notes & references

- Cloud security centres on **identity and misconfiguration** far more than on
  memory-level OS internals — focus on IAM policies, storage exposure, and
  secrets handling.
- For tooling (Trivy, kube-bench, Kubescape, ScoutSuite, Docker hardening) and container
  escape topics, see [Containers & Cloud Security](../containers-cloud/).
- The privileged-container escape in
  [Sample Walkthroughs](../methodology/sample-walkthroughs.md) shows why
  container/host isolation matters in cloud-hosted workloads.
