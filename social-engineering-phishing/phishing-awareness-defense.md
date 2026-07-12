# Phishing Awareness & Defense

> The blue-team side of this category: how to recognize phishing, the email
> authentication stack (SPF/DKIM/DMARC) that blunts spoofing, user-training and
> reporting habits, and where to pull live phishing intel.

- **Link:** https://www.cisa.gov/secure-our-world/recognize-and-report-phishing
- **Type:** concept / defensive reference

## Description

Every offensive tool in this category exists so defenders can measure and improve
resistance to it. Real defense is layered: authenticate inbound mail so spoofing
is hard, train people to recognize the pretext, make reporting a suspicious
message effortless, and enforce phishing-resistant MFA so a stolen password or
relayed OTP isn't game over. This page is the reference for that layered stack.

## Recognizing phishing

- **Sender / domain mismatch** — display name says one thing, the actual address
  or reply-to is a look-alike (`micros0ft.com`, `paypa1-secure.com`).
- **Urgency and fear** — "account will be suspended," "invoice overdue," pressure
  to act before you think.
- **Unexpected links / attachments** — hover to reveal the real URL; watch for
  homoglyph and punycode domains and mismatched link text.
- **Credential prompts** — a login page reached from an email link, especially on
  a domain that isn't the service's real one (the tell that catches reverse-proxy
  kits like [evilginx2](evilginx2.md) *if* users check the address bar).
- **Too good / out of character** — gift cards, refunds, or a "CEO" texting an
  odd request (business email compromise).

## Email authentication: SPF, DKIM, DMARC

These three DNS-published records let receiving servers verify that mail claiming
to be from your domain is legitimate. Deploy all three.

```dns
; SPF — list the hosts authorized to send mail for the domain
example.com.  IN TXT  "v=spf1 include:_spf.google.com -all"

; DKIM — publish the public key that signs outbound mail (selector "s1")
s1._domainkey.example.com.  IN TXT  "v=DKIM1; k=rsa; p=MIGfMA0GCSq...AQAB"

; DMARC — tell receivers what to do when SPF/DKIM fail, and where to send reports
_dmarc.example.com.  IN TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s"
```

- **SPF** authorizes sending IPs; **DKIM** cryptographically signs the message;
  **DMARC** ties them to the visible `From:` domain (alignment) and sets policy
  (`none` → monitor, `quarantine`, `reject`) plus aggregate reporting (`rua`).
- Start at `p=none` to collect reports, review the DMARC aggregate data, then move
  to `quarantine` and finally `reject` once legitimate senders pass.
- Verify records with free checkers such as https://www.mail-tester.com and
  https://dmarc.org/resources/.

## User training & reporting

- **Run authorized simulations** and track the click rate over time — baseline,
  train, re-test. Tooling: [Gophish](gophish.md), [King Phisher](king-phisher.md).
- **Make reporting one click** — a "Report Phish" button that routes to the SOC
  beats asking users to forward-as-attachment.
- **Reward reporting, don't punish clicking** — a blame-free culture surfaces more
  real attacks; treat a click as a coaching moment, not a gotcha.
- **Enforce phishing-resistant MFA** — FIDO2/WebAuthn
  [security keys](../hardware/security-keys.md) stop credential-and-token theft
  that SMS/OTP cannot, because the credential is bound to the real site's origin.

## Detection & response (blue team)

- Alert on logins from look-alike domains, impossible-travel session reuse, and
  new-device sessions right after an auth event (evilginx-style token replay).
- Feed IOC/URL feeds into mail and web filtering; sinkhole or block confirmed
  phishing domains at the resolver/proxy.
- Have an incident runbook: contain the reporting user's session, revoke tokens,
  reset credentials, and hunt for others who received the same lure.

## Notes & references

- Live phishing/URL intel to feed filters and enrich alerts is catalogued in
  [Learning Resources → News & Feeds](../learning-resources/news-and-feeds.md)
  (OpenPhish, PhishTank, URLhaus).
- Detection and monitoring tooling lives in
  [Defense & Blue Team](../defense-blueteam/) — SIEM/IDS, endpoint telemetry,
  and log analysis to catch the follow-on activity.
- DMARC standard and deployment guidance: https://dmarc.org
- CISA phishing guidance: https://www.cisa.gov/secure-our-world/recognize-and-report-phishing
