# MITRE ATT&CK

> A globally accessible, continuously updated knowledge base of real-world
> adversary behaviour, organized as tactics (the *why*) and techniques (the
> *how*). The common vocabulary for describing what attackers actually do.

- **Link:** https://attack.mitre.org
- **Type:** free / open knowledge base

## Description

Where the [Cyber Kill Chain](cyber-kill-chain.md) gives you the broad phases of
an intrusion, ATT&CK fills them in with hundreds of concrete techniques observed
in the wild, each documented with examples, detection ideas, and mitigations. It
is maintained by MITRE from public threat-intelligence reporting, so it reflects
how real groups operate rather than theory. Red teams use it to plan and scope
engagements; blue teams use it to measure detection coverage and drive threat
hunting.

## How it's structured

- **Tactics** — the adversary's goal at a given step (e.g. *Initial Access*,
  *Execution*, *Persistence*, *Privilege Escalation*, *Defense Evasion*,
  *Credential Access*, *Discovery*, *Lateral Movement*, *Collection*,
  *Command and Control*, *Exfiltration*, *Impact*). These are the columns of the
  ATT&CK matrix.
- **Techniques & sub-techniques** — the specific methods used to achieve a tactic
  (e.g. *T1059 Command and Scripting Interpreter*). Each has a stable ID, a
  description, real-world procedure examples, detections, and mitigations.
- **Matrices** — separate technique sets for **Enterprise** (Windows, Linux,
  macOS, cloud, containers), **Mobile** (Android, iOS), and **ICS**.
- **Groups & Software** — catalogued threat actors and malware/tools, mapped to
  the techniques they are known to use.

## How it's used

- **Detection coverage** — map your existing alerts to technique IDs to find
  blind spots.
- **Threat hunting** — pick a technique relevant to your threat model and hunt
  for its behaviour.
- **Red team planning & reporting** — scope emulation to a specific group and
  report findings using shared IDs.
- **Adversary emulation** — reproduce a known group's technique chain to test
  defences.

## Notes & references

- Techniques are referenced by ID (e.g. `T1566` Phishing) — use these IDs in
  notes and reports so findings are unambiguous.
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) is a free
  tool for building coverage heatmaps over the matrix.
- Pairs naturally with the [Cyber Kill Chain](cyber-kill-chain.md) (phases) and
  with defensive tooling in [Defensive Security & Blue Team](../defense-blueteam/).
