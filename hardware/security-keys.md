# Security Keys (YubiKey / FIDO2)

> Hardware authenticators that hold cryptographic secrets in a tamper-resistant
> chip, giving you phishing-resistant MFA, passwordless login, SSH keys, and
> more — the credential never leaves the device.

- **Link:** https://www.yubico.com
- **Type:** commercial (hardware)
- **Platform:** cross-platform (USB-A / USB-C / Lightning / NFC)

## Description

A security key is a small hardware token that performs public-key cryptography
on-device. Because the private key is generated on the key and can never be
extracted, an attacker who phishes your password still can't log in without the
physical token — and the FIDO2/WebAuthn protocol binds each credential to the
real site's origin, so it resists phishing and man-in-the-middle proxies that
defeat OTP codes. **Yubico's YubiKey** is the top-tier, industry-standard
family; **Security Key NFC** is Yubico's cheaper FIDO-only line.

Typical uses:

- **MFA / 2FA** for cloud, email, VPN, and admin consoles (FIDO2/U2F).
- **Passwordless** login (FIDO2 resident keys / passkeys).
- **SSH** authentication (FIDO-backed `ed25519-sk` / `ecdsa-sk` keys, or PIV).
- **PGP/GPG**, smart-card (PIV), and TOTP secrets stored on the key.

## Models worth knowing

| Model | Notes |
| --- | --- |
| YubiKey 5 Series | Flagship; supports FIDO2/U2F, PIV, OpenPGP, OATH-TOTP, and more (USB-A/C, NFC variants) |
| Security Key NFC | Budget line — FIDO2/U2F only, no PIV/PGP |
| YubiKey 5 FIPS | FIPS 140-2/140-3 validated (current 5.7 series is 140-3), for regulated environments |

## Usage examples

```bash
# Generate an SSH key backed by the hardware key (touch required to auth)
ssh-keygen -t ed25519-sk -O resident -C "yubikey"

# Load resident FIDO keys from the hardware key into the agent
ssh-add -K
# Copy the public key to a server (append the *.pub to authorized_keys)
ssh-copy-id -f -i ~/.ssh/id_ed25519_sk.pub user@server
```

## Notes & references

- **Buy two and register both** — a backup key saves you from a lockout if the
  primary is lost or damaged.
- Phishing-resistant MFA (FIDO2/WebAuthn) is strictly stronger than SMS or TOTP,
  which can be relayed by a reverse-proxy phishing kit.
- Free `ykman` CLI and YubiKey Manager GUI configure slots and modes.
- Docs & developer guides: https://developers.yubico.com
