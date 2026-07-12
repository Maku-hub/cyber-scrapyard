# Gophish

> Open-source phishing framework for running end-to-end awareness campaigns:
> build email templates and landing pages, send to target groups, and track
> opens, clicks, and submitted credentials from a web dashboard.

- **Link:** https://github.com/gophish/gophish
- **Type:** open source
- **Platform:** cross-platform (single Go binary — Linux / Windows / macOS)

## Description

Gophish is the go-to tool for authorized phishing *simulations* and
security-awareness testing. It ships as a self-contained Go binary with a web
admin UI where you define sending profiles (SMTP), email templates, landing
pages, and target groups, then launch a campaign and watch a real-time timeline
of who opened, who clicked, and who entered data. Because the whole workflow is
measurable, it's ideal for baselining an organization's click rate and showing
improvement after training — not for attacking third parties.

## Installation

```bash
# Download the release for your OS, unzip, and run the binary
# (grab the latest build from the releases page)
unzip gophish-v0.12.1-linux-64bit.zip -d gophish
cd gophish && ./gophish
```

## Usage examples

```bash
# Start the server — admin UI on https://127.0.0.1:3333, phishing listener on :80
./gophish
```

The admin console prints a randomly generated password on first launch. Edit
`config.json` to bind the admin/phishing interfaces to the right addresses
before exposing anything.

```json
// config.json — bind admin locally, phishing server on all interfaces
{
  "admin_server": { "listen_url": "127.0.0.1:3333", "use_tls": true },
  "phish_server": { "listen_url": "0.0.0.0:80", "use_tls": false }
}
```

Typical campaign flow in the UI:

```text
1) Sending Profiles  # configure the SMTP relay used to send test mail
2) Email Templates   # craft the message (import raw HTML, add {{.Tracker}})
3) Landing Pages     # clone/import a page; enable "Capture Submitted Data"
4) Users & Groups    # import the authorized target list (CSV)
5) Campaigns         # tie it together, launch, and watch the results timeline
```

## Notes & references

- Template variables like `{{.FirstName}}`, `{{.URL}}`, and `{{.Tracker}}`
  personalize mail and embed the open-tracking pixel.
- Run only against your own users under a written awareness-testing scope; handle
  any captured data per your engagement's data-handling rules.
- REST API lets you script campaign creation and pull results programmatically.
- For the reverse-proxy technique that also captures MFA session tokens, see
  [evilginx2](evilginx2.md); for defensive controls and reporting, see
  [Phishing Awareness & Defense](phishing-awareness-defense.md).
- Docs & user guide: https://docs.getgophish.com
