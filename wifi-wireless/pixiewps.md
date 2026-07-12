# Pixiewps

> An offline brute-forcer for the WPS "Pixie Dust" attack — when a router's WPS
> implementation uses weak randomness, it recovers the PIN in seconds without
> ever touching the access point again.

- **Link:** https://github.com/wiire-a/pixiewps
- **Type:** open source
- **Platform:** Linux

## Description

The Pixie Dust attack exploits access points that generate the two secret nonces
(`E-S1`/`E-S2`) used in the WPS exchange with little or no entropy. When that's
the case, an attacker only needs to capture a single WPS handshake and can then
compute the PIN *offline*, instead of running the slow online PIN brute force
against the router. Pixiewps is the tool that does that offline computation: you
feed it the public keys and hashes collected from one exchange, and it derives
the WPS PIN — often in under a second. In practice you rarely call it by hand;
`reaver -K` captures the values and invokes it for you (see the online-attack
side in [WPS attacks](wps-attacks.md)).

## Installation

```bash
sudo apt install pixiewps        # Debian/Kali/Ubuntu

# Or build the latest from source
git clone https://github.com/wiire-a/pixiewps.git
cd pixiewps && make && sudo make install
```

## Usage examples

```bash
# Easiest path: let reaver capture the handshake and run pixiewps automatically
sudo reaver -i wlan0mon -b <AP_BSSID> -c <CHANNEL> -K 1 -vv

# Manual mode: supply the values captured from the WPS exchange
#   -e enrollee pubkey, -r registrar pubkey, -s/-z E-Hash1/2, -a auth session key, -n enrollee nonce
pixiewps -e <PKE> -r <PKR> -s <E-Hash1> -z <E-Hash2> -a <AuthKey> -n <E-Nonce>

# Show all options, including forcing a specific mode/vendor
pixiewps --help
```

## Notes & references

- Pixiewps is the **offline cracker**; capturing the WPS material and doing the
  online fallback is [Reaver/Bully](wps-attacks.md)'s job — the two are almost
  always used together.
- Only APs with vulnerable WPS chipsets/firmware fall to Pixie Dust; a patched or
  WPS-locked router won't, and you drop back to the online PIN brute force.
- [Wifite](wifite.md) drives the whole Pixie Dust flow automatically (`--wps`),
  including calling pixiewps under the hood.
- The fix, as always with WPS, is to **disable WPS** on the router.
- Background on why WPS is weak: [Wi-Fi security overview](wifi-security-overview.md).
