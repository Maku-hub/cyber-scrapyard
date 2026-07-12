# Example Scenarios

End-to-end walkthroughs that chain the tools in this repo into a realistic
engagement. Where the category pages answer *"what is this tool and how do I run
it?"*, these scenarios answer *"I'm faced with X — which tools, in what order,
and why?"* Every step links to the relevant tool page.

> ⚠️ **Authorized use only.** These playbooks describe testing you perform
> against systems you own or are explicitly contracted/permitted to assess.
> Always work within a written scope and rules of engagement.

## Scenarios

| Scenario | You have… | Goal |
| --- | --- | --- |
| [External Recon & OSINT](external-recon-osint.md) | Just an organisation's name/domain | Map the external footprint passively before touching anything |
| [Web Application Assessment](web-app-assessment.md) | A target web app / URL | Find and validate web vulnerabilities |
| [Internal Network & Active Directory](internal-network-ad.md) | A foothold on a corporate LAN | Enumerate the network and work toward Domain Admin |
| [Linux Server Assessment](linux-server-assessment.md) | A single Linux/Debian server | Assess exposure, patch level, config hardening, and local privesc |
| [Wi-Fi Assessment](wifi-assessment.md) | A wireless network in scope | Test the Wi-Fi's encryption and client exposure |
| [Container & Image Security](container-security-pipeline.md) | A container image / K8s cluster | Scan the supply chain and runtime for weaknesses |
| [Malware Triage](malware-triage.md) | A suspicious file (blue-team) | Safely determine what a sample does |

## How to read these

Each scenario is a numbered flow: **phase → tool → what you're looking for →
next step**. They're deliberately opinionated (a sensible default path), not
exhaustive — swap in alternatives from the linked category as the situation
demands. They map loosely onto the phases in
[Methodology & Frameworks](../methodology/).
