# Zphisher

> Automated, menu-driven toolkit that spins up prebuilt phishing pages for common
> services behind a tunneling service — a quick way to demonstrate credential
> harvesting in an authorized awareness test.

- **Link:** https://github.com/htr-tech/zphisher
- **Type:** open source
- **Platform:** Linux / macOS / Termux (Bash)

## Description

Zphisher is a Bash script that automates the setup most phishing demos need: it
serves one of many bundled login-page templates and exposes it over a tunnel
(Cloudflared, LocalXpose, or Ngrok) so the demo link works without configuring a
public server. It's popular for quick classroom/awareness demonstrations of how
convincing a cloned login page can be and how easily credentials are captured —
strictly against consenting participants. It is a demonstration toolkit, not a
campaign platform: for tracked, group-based simulations use [Gophish](gophish.md).

## Installation

```bash
# Clone and run
git clone https://github.com/htr-tech/zphisher.git
cd zphisher && bash zphisher.sh
```

## Usage examples

```bash
# Launch the interactive menu
bash zphisher.sh
```

The script is entirely menu-driven:

```text
1) Pick a template from the list (various common login pages)
2) Choose a port and a tunnel option (Cloudflared / LocalXpose / Ngrok)
3) Share the generated link ONLY with consenting test participants
4) Captured credentials print to the terminal and save to auth/ locally
```

## Notes & references

- Reference/awareness use only — hosting a look-alike login for real,
  non-consenting users is illegal in most jurisdictions.
- The bundled templates are for illustrating recognition training; pair a demo
  with the checklist in
  [Phishing Awareness & Defense](phishing-awareness-defense.md).
- Tunnel links are ephemeral and easily flagged; treat this as a teaching aid,
  not production tooling.
- Repo & template list: https://github.com/htr-tech/zphisher
