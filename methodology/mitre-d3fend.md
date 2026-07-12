# MITRE D3FEND

> A knowledge graph of defensive countermeasures — the blue-team companion to
> ATT&CK. Where ATT&CK catalogues what attackers do, D3FEND catalogues the
> techniques that detect, harden against, isolate, deceive, or evict them.

- **Link:** https://d3fend.mitre.org/
- **Type:** free / open knowledge base

## Description

D3FEND is a MITRE knowledge base that gives defensive measures the same
structured, referenceable treatment [MITRE ATT&CK](mitre-attack.md) gives
offensive ones. It organises countermeasures into a graph and — crucially — maps
them back to the attacker techniques they counter, so you can move from "the
adversary uses T1059 Command and Scripting Interpreter" to "these defensive
techniques address it." That mapping turns a threat model into a concrete,
justified control set, which is why it shows up in architecture reviews and
detection-engineering discussions.

## How it's structured

- **Defensive tactics** — the top-level categories of defensive action:
  **Model**, **Harden**, **Detect**, **Isolate**, **Deceive**, **Evict**, and
  **Restore**.
- **Defensive techniques** — specific countermeasures under each tactic (e.g.
  *File Analysis*, *Network Traffic Analysis*, *Executable Denylisting*,
  *Credential Rotation*), each with a stable D3FEND ID.
- **Digital Artifacts** — the ontology of things defences act on (processes,
  files, network nodes). Artifacts are the pivot: an ATT&CK technique *produces
  or touches* an artifact, and a D3FEND technique *operates on* that same
  artifact — which is how the two knowledge bases link.

## How it's used

- **Control selection** — justify which defensive techniques to invest in by
  tracing them to the ATT&CK techniques in your threat model.
- **Coverage gap analysis** — pair with ATT&CK: overlay the techniques you can
  detect/mitigate against the ones adversaries use, and find the gaps.
- **Architecture & product evaluation** — describe what a control *actually does*
  in vendor-neutral terms rather than by marketing category.
- **Detection engineering** — reason about which digital artifacts a detection
  observes and therefore which techniques it can plausibly catch.

## Notes & references

- Techniques carry stable IDs (e.g. `D3-NTA` Network Traffic Analysis) — cite
  them the way you'd cite ATT&CK `T####` IDs.
- Direct companion to [MITRE ATT&CK](mitre-attack.md); use them together to move
  from adversary behaviour to countermeasure.
- Feeds directly into the tooling in
  [Defensive Security & Blue Team](../defense-blueteam/).
- Reference: <https://d3fend.mitre.org/>
