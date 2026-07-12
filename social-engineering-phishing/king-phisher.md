# King Phisher

> Full-featured phishing campaign toolkit with a client/server architecture,
> a GUI campaign manager, and detailed per-recipient tracking — built for
> running and measuring authorized awareness programs.

- **Link:** https://github.com/rsmusllp/king-phisher
- **Type:** open source
- **Platform:** Linux (server + GTK client)

## Description

King Phisher separates a headless server (which sends mail and hosts landing
pages) from a GTK desktop client used to design campaigns, so a team can run
larger, longer-lived awareness programs than a single-binary tool comfortably
handles. It supports customizable email/web content with Jinja2 templating,
per-recipient tracking (opens, clicks, submitted credentials), optional
two-factor for the operator console, and a plugin system for extending campaigns.
It fills the same niche as [Gophish](gophish.md); pick it when you want the
client/server split and plugin extensibility.

> **Note:** development has stalled (last release v1.15.0, 2021) and the project
> is not actively maintained, though it still runs. For new awareness programs
> the better-maintained default is [Gophish](gophish.md); reach for King Phisher
> only if you specifically want the client/server split and plugin system.

## Installation

```bash
# Server install via the maintained setup script (Linux)
sudo apt install python3 python3-pip
wget https://github.com/rsmusllp/king-phisher/raw/master/tools/install.sh
sudo bash install.sh

# Launch the GTK client (connects to the server over SSH)
king-phisher
```

## Usage examples

King Phisher is GUI-driven; a campaign follows this path in the client:

```text
1) Connect the client to the server over SSH
2) Create a campaign and import the authorized recipient list
3) Design the message (Jinja2 vars) and the landing/credential page
4) Configure the SMTP sending profile and send
5) Review the dashboard: opened, clicked, and credentials-submitted per user
```

```jinja
{# Message template variables personalize each email and embed tracking #}
Hello {{ client.first_name }}, please review: {{ url.webserver }}
```

## Notes & references

- Restrict campaigns to your own users under a documented awareness-testing
  scope; store any captured data per your rules of engagement.
- Server hosts landing pages and logs visits; the SSH-tunneled client keeps the
  operator console off the public internet.
- Defensive counterpart: [Phishing Awareness & Defense](phishing-awareness-defense.md).
- Docs: https://king-phisher.readthedocs.io
