# Antivirus & EDR Concepts

> How modern endpoint protection actually decides something is malicious —
> static, dynamic, and behavioural analysis — and what that means for defenders
> and red teamers alike.

- **Link:** https://attack.mitre.org/ (behavioural detection maps to ATT&CK)
- **Type:** concept reference (not a single tool)
- **Platform:** cross-platform (Windows/Linux/macOS endpoints)

## Description

This page is a themed reference rather than a tool page. Endpoint security
products (traditional AV and modern EDR) combine several detection strategies.
Understanding them explains why some malware slips through, why sandboxes exist,
and why behavioural detection is the current centre of gravity.

## The three layers of analysis

### Static analysis

Inspecting a file **without running it** — matching signatures against known-bad
indicators: file hashes/checksums, embedded strings, domains, IP addresses, byte
patterns. Fast and cheap, and effective against known malware, but defeated by
any novel or repacked sample. The newer variant is ML-based file classification
trained on large static malware corpora.

### Dynamic analysis

Modern AV goes beyond signatures by **running the file in a sandbox** — an
emulated execution environment — and watching what it does: attempts to decrypt
and read browser passwords, dumping LSASS, injecting into other processes,
reaching out to C2. The sandbox can be local (on the endpoint) or cloud-based.

> Trivia: the sandbox machine hostname in Windows Defender has historically been
> **`HAL9TH`** — malware that checks the hostname and exits when it sees a known
> sandbox name is performing *sandbox/VM evasion*.

### Behavioural analysis

**EDR** (Endpoint Detection & Response) leans on behavioural analysis of a
running application to spot suspicious *sequences of actions* rather than a
single bad file. Example: a process spawning `whoami`, then quickly running other
discovery/enumeration commands in a tight window — individually benign, but the
pattern is a classic post-exploitation footprint. EDR ties these events to a
process tree, scores them, and can kill, quarantine, or isolate the host.

## Sandbox / EDR evasion (defender's awareness)

Attackers commonly try to detect the analysis environment before doing anything
malicious. Awareness of these techniques helps blue teams harden sandboxes:

- Check the hostname/username/domain against known sandbox values (e.g. `HAL9TH`).
- Look for VM artefacts: MAC prefixes, drivers, registry keys, low core/RAM counts.
- Stall or sleep to outlast a time-boxed sandbox run.
- Require user interaction (mouse movement, document scrolling) before detonating.

## Notes & references

- Behavioural detections map cleanly onto **MITRE ATT&CK** techniques —
  https://attack.mitre.org/
- Detonate suspicious samples safely in cloud sandboxes like ANY.RUN, Hybrid
  Analysis, or Joe Sandbox (see [Reverse Engineering & Malware](../reverse-engineering-malware/)).
- On Windows, [Sysmon](sysmon.md) provides much of the raw behavioural telemetry
  an EDR would consume; [Wazuh](wazuh.md) adds open-source XDR-style correlation.
- Signature-based detection at the network layer is the [Snort](snort.md) /
  [Suricata](suricata.md) analogue of static AV.
