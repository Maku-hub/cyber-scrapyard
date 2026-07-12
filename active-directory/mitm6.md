# mitm6

> IPv6/DHCPv6 DNS takeover. Windows prefers IPv6 and asks for a DHCPv6 lease by
> default, so mitm6 replies as the DNS server and quietly reroutes name
> resolution to your host — the classic partner for an NTLM relay.

- **Link:** https://github.com/dirkjanm/mitm6
- **Type:** open source
- **Platform:** cross-platform (Python; typically run from Linux/Kali)

## Description

Even on IPv4-only networks, Windows machines send out DHCPv6 solicitations
looking for an IPv6 configuration. mitm6 answers those requests, hands the
victim an IPv6 address, and — crucially — advertises *your* host as its DNS
server. From then on the victim resolves names through you, letting you answer
selected lookups (e.g. WPAD) and funnel the resulting authentication into a
relay. Unlike broadcast poisoning, this abuses default IPv6 behaviour rather
than a fallback protocol, so it often works where LLMNR/NBT-NS has been
disabled. In practice mitm6 is paired with [ntlmrelayx](impacket.md): mitm6
supplies the coerced traffic, ntlmrelayx relays it to LDAP/SMB.

## Installation

```bash
# Install with pipx (isolated) or pip
pipx install mitm6

# Or from source
git clone https://github.com/dirkjanm/mitm6
```

## Usage examples

```bash
# Poison DHCPv6/DNS for a single AD domain
sudo mitm6 -d corp.local

# Limit the blast radius to one host (reduce noise / scope creep)
sudo mitm6 -d corp.local --host-allowlist 10.0.0.50

# Choose the interface explicitly
sudo mitm6 -i eth0 -d corp.local
```

The usual pairing hands the coerced auth to [ntlmrelayx](impacket.md):

```bash
# Relay the incoming NTLM auth to LDAP over TLS and serve a rogue WPAD file
impacket-ntlmrelayx -6 -t ldaps://dc01.corp.local -wh wpad.corp.local
```

## Notes & references

- Run mitm6 and ntlmrelayx in separate terminals; mitm6 does the IPv6/DNS
  takeover, ntlmrelayx receives and relays the authentication.
- Scope it. Left unbounded it will answer for the whole segment — always use
  `-d`/`--host-allowlist` on an authorized engagement to stay in scope.
- Defence: block rogue DHCPv6 with RA Guard/DHCPv6 Guard, disable IPv6 only if
  truly unused, and enforce SMB/LDAP signing plus channel binding so relayed
  auth fails.
- Pairs with [Responder](responder.md) (IPv4 poisoning) and
  [coercion tools](coercion-tools.md) as sources of relayable authentication.
- Author write-up (mitm6 + relay attack): https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/