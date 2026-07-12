# Cyber Kill Chain

> Lockheed Martin's model that breaks an intrusion into seven ordered phases.
> Mapping activity onto the chain helps both attackers plan and defenders detect
> and disrupt an attack at the earliest possible stage.

- **Link:** https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- **Type:** conceptual framework

## Description

The Cyber Kill Chain describes the lifecycle of a targeted attack as a sequence
of steps an adversary must complete to reach their goal. Its value is defensive:
the earlier in the chain you break the sequence, the cheaper the incident. It
pairs well with [MITRE ATT&CK](mitre-attack.md), which fills in the concrete
techniques used within each phase.

## The seven phases

1. **Reconnaissance** — gathering information about the target (hosts, services,
   people, technologies) to identify a way in.
2. **Weaponization** — combining an exploit with a payload into a deliverable
   artifact, such as a malicious document or crafted request.
3. **Delivery** — transmitting the weapon to the target (email, web, USB, exposed
   service).
4. **Exploitation** — triggering the vulnerability to execute the attacker's code
   on the target.
5. **Installation** — establishing a foothold by installing malware or a
   persistence mechanism.
6. **Command & Control (C2)** — opening a channel back to the attacker so the
   compromised host can be operated remotely.
7. **Actions on Objective** — achieving the real goal: data theft, lateral
   movement, destruction, or ransom.

## Notes & references

- Defenders aim to detect and respond as early as possible — recon and delivery
  are cheaper to disrupt than actions on objective.
- Maps cleanly onto ATT&CK tactics; use both together when planning detections.
- Reference: <https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html>
