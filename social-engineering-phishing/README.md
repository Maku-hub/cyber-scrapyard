# Social Engineering & Phishing

Tools and references for the human attack surface: phishing simulations,
credential-harvesting demonstrations, and — just as importantly — the defenses
that blunt them. Social engineering targets people rather than software, so this
category pairs offensive tooling with awareness training and email-authentication
controls.

> **Authorized use only.** Everything here is for red-team engagements and
> security-awareness testing against consenting participants under a written
> rules-of-engagement scope. Phishing real third parties without authorization is
> illegal. Pages are kept reference-level — no turnkey live lures.

## Tools

| Tool | Summary |
| --- | --- |
| [Gophish](gophish.md) | Open-source phishing framework — build campaigns and track opens/clicks/submissions from a web dashboard |
| [Evilginx2](evilginx2.md) | Reverse-proxy phishing that captures credentials **and** session tokens, defeating non-phishing-resistant MFA |
| [Zphisher](zphisher.md) | Automated, menu-driven toolkit that serves prebuilt phishing pages over a tunnel — quick awareness demos |
| [King Phisher](king-phisher.md) | Client/server phishing campaign toolkit with GUI, per-recipient tracking, and plugins |
| [Phishing Awareness & Defense](phishing-awareness-defense.md) | Blue-team side: recognizing phishing, SPF/DKIM/DMARC, training, reporting, detection |

## Related tools elsewhere in the repo

- **[Social-Engineer Toolkit (SET)](../exploitation-c2/social-engineer-toolkit.md)** —
  TrustedSec's menu-driven framework for spear-phishing, site cloning, and payload
  delivery wired to Metasploit. It lives with the exploitation/C2 tooling because
  of that Metasploit integration.

## How the pieces fit

1. **Baseline** — run an authorized simulation and measure the click/submit rate
   ([Gophish](gophish.md), [King Phisher](king-phisher.md)).
2. **Demonstrate impact** — show *why* MFA alone isn't enough with a reverse-proxy
   token-theft demo ([Evilginx2](evilginx2.md)) in a lab.
3. **Train & re-test** — teach recognition, make reporting one click, and re-run
   the simulation to show improvement.
4. **Harden** — deploy SPF/DKIM/DMARC and phishing-resistant MFA so a click or a
   stolen OTP no longer means compromise
   ([Phishing Awareness & Defense](phishing-awareness-defense.md)).

> Rule of thumb: **the strongest single control against these attacks is
> phishing-resistant MFA** — FIDO2/WebAuthn
> [security keys](../hardware/security-keys.md) resist even the reverse-proxy
> kits that relay OTP and push codes.

## See also

- [Hardware → Security Keys](../hardware/security-keys.md) — the FIDO2 defense
  that evilginx-style token theft cannot bypass.
- [Defense & Blue Team](../defense-blueteam/) — detection and monitoring for the
  follow-on activity after a lure lands.
- [Learning Resources → News & Feeds](../learning-resources/news-and-feeds.md) —
  live phishing/URL intelligence feeds (OpenPhish, PhishTank, URLhaus).
- [Exploitation & C2](../exploitation-c2/) — SET and the payload/listener tooling
  a phishing lure hands off to.
