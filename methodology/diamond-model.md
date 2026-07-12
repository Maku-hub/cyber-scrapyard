# Diamond Model of Intrusion Analysis

> A framework for analysing a single intrusion as the relationship between four
> core features — adversary, capability, infrastructure, and victim — connected
> by the edges that let an analyst pivot from one to the next.

- **Link:** https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf
- **Type:** conceptual framework

## Description

The Diamond Model, introduced by Caltagirone, Pendergast, and Betz, structures
threat intelligence around a single atomic event: an **adversary** uses a
**capability** over some **infrastructure** against a **victim**. Drawing those
four vertices and the edges between them gives analysts a disciplined way to
record what is known and, more importantly, to *pivot* — a malicious domain
(infrastructure) resolves to an IP that hosts other malware (capability) tied to
the same actor (adversary), and so on. Where the [Cyber Kill Chain](cyber-kill-chain.md)
describes the *phases* of an attack and [MITRE ATT&CK](mitre-attack.md) catalogues
the *techniques*, the Diamond Model is the analytic method for connecting the
evidence of one intrusion into a coherent picture.

## The four core features

1. **Adversary** — the actor (or operator/customer pair) behind the intrusion:
   who is conducting or benefiting from it.
2. **Capability** — the tools, techniques, and malware employed (its "capacity"),
   from a phishing lure to a custom implant.
3. **Infrastructure** — the physical/logical assets used to deliver the
   capability and control it: C2 domains, IP addresses, email accounts.
4. **Victim** — the target: the organisation, people, assets, or systems the
   adversary acts against.

## Meta-features & pivoting

- **Meta-features** enrich each event: timestamp, phase, result, direction,
  methodology, and resources — plus optional *social-political* (the adversary's
  intent/relationship to the victim) and *technology* axes.
- **Pivoting** is the core analytic move: start from any known vertex and follow
  an edge to discover a connected one (e.g. from a victim's malware sample to the
  infrastructure it beacons to, then to other victims of the same infrastructure).
- **Activity threads** chain multiple diamonds across kill-chain phases, letting
  you cluster related events into campaigns and attribute them to an actor.

## Notes & references

- Complements [Cyber Kill Chain](cyber-kill-chain.md) (phase sequencing) and
  [MITRE ATT&CK](mitre-attack.md) (technique catalogue); the model's authors
  explicitly recommend using the kill chain alongside it.
- Widely used to structure CTI reporting and to drive pivoting during
  [Digital Forensics & Incident Response](../forensics-ir/).
- Original paper: <https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf>
