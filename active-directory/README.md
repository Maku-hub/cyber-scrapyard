# Active Directory

Active Directory is Microsoft's identity and access-management service, and it
runs the network in most corporate environments. Because so much is bolted onto
it — authentication protocols, delegation, certificate services, group policy —
it also carries a large attack surface. This category collects the tools you
reach for on an authorized AD penetration test: from getting an initial foothold
by poisoning name resolution, through enumerating the domain and cracking or
relaying credentials, to mapping attack paths up to Domain Admin.

> ⚠️ **Authorized use only.** AD penetration testing is a standard professional
> skill, but everything here is for labs, CTFs, and engagements you are
> explicitly permitted to perform. Test only systems you own or have written
> permission to assess.

## Tools

| Tool | Summary |
| --- | --- |
| [Responder](responder.md) | LLMNR/NBT-NS/MDNS poisoner — captures NetNTLM(v1/v2) hashes for cracking or relay |
| [Inveigh](inveigh.md) | Windows PowerShell/C# LLMNR/NBT-NS/mDNS spoofer — the Windows-side counterpart to Responder |
| [mitm6](mitm6.md) | IPv6/DHCPv6 DNS takeover — reroutes name resolution to your host; pairs with ntlmrelayx |
| [Coercion Tools](coercion-tools.md) | PetitPotam, Coercer, PrinterBug/MS-RPRN — force a DC to authenticate for relay |
| [NetExec (nxc)](netexec.md) | Multi-protocol AD enumeration & lateral movement; the maintained successor to CrackMapExec |
| [BloodHound](bloodhound.md) | Graph-based AD attack-path mapping (with the SharpHound collector) |
| [PowerView](powerview.md) | PowerShell AD enumeration (users, ACLs, trusts, sessions); Python port PowerView.py |
| [Impacket](impacket.md) | Python toolkit: secretsdump, Get-GPPPassword, GetUserSPNs, GetNPUsers, psexec/wmiexec, ntlmrelayx |
| [Evil-WinRM](evil-winrm.md) | Interactive WinRM shell with pass-the-hash and file transfer |
| [SMB Tools](smb-tools.md) | smbclient, smbmap, enum4linux-ng — share enumeration and access |
| [Snaffler](snaffler.md) | Hunts domain SMB shares for credentials, keys, config secrets and PII |
| [Kerberos Attacks](kerberos-attacks.md) | Kerberoasting & AS-REP roasting concepts + Rubeus and Kerbrute |
| [AD Certificate Services](ad-certificate-services.md) | ADCS abuse (ESC1 etc.) with Certipy |
| [PingCastle](pingcastle.md) | AD security-audit / health-check tool with a risk-scored report (blue-team; licence caveat) |
| [Mimikatz](../post-exploitation/mimikatz.md) | Credential dumping & pass-the-hash on Windows (see Post-Exploitation) |

## AD attack workflow

A representative internal AD chain, adapted from field notes. Each step feeds
the next; not every engagement needs all of them.

1. **Get a foothold via name-resolution poisoning.** LLMNR and NBT-NS are on by
   default. Run [Responder](responder.md) to answer broadcasts and capture
   NetNTLMv1/v2 hashes.
2. **Use the captured hash.** NetNTLMv1 is weak — downgrade/relay it or crack it
   quickly. NetNTLMv2 is relayable *only if the target does not enforce SMB
   signing*; otherwise crack it offline with Hashcat (mode 5600). If relay is
   viable, forward it with `impacket-ntlmrelayx`.
3. **Log in with recovered credentials.** RDP (`xfreerdp /u: /d: /p: /v:`) or
   [Evil-WinRM](evil-winrm.md) if WinRM is exposed.
4. **Dump local secrets.** Run [Mimikatz](../post-exploitation/mimikatz.md)
   (`privilege::debug`, `sekurlsa::logonpasswords`) or export the SAM/SECURITY/
   SYSTEM hives (`reg save HKLM\SYSTEM system.bin` …) and run
   `impacket-secretsdump ... LOCAL` to recover cached domain NTLM hashes.
5. **Move laterally with the NTLM hash (Pass-the-Hash).** Spray it with
   [NetExec](netexec.md) (`nxc smb <range> -u <user> -H <hash>`) to find where it
   grants local admin (`Pwn3d!`), or use `sekurlsa::pth` in Mimikatz.
6. **Enumerate the domain.** [SMB tools](smb-tools.md) and [NetExec](netexec.md)
   for shares/LDAP/users; [BloodHound](bloodhound.md) to map attack paths to
   Domain Admin.
7. **Attack Kerberos.** [Kerberoast and AS-REP roast](kerberos-attacks.md) service
   and preauth-disabled accounts, then crack offline (Hashcat modes 13100 / 18200).
8. **Escalate via AD CS.** If a Certificate Authority is present, hunt for
   vulnerable templates with [Certipy](ad-certificate-services.md) (ESC1 etc.) to
   mint a certificate that authenticates as a privileged account.
9. **Reach Domain Admin & DCSync.** With replication rights,
   `impacket-secretsdump` against the DC dumps the entire domain (NTDS.dit).

> **Hardening takeaways:** disable LLMNR/NBT-NS, enforce SMB signing, require
> strong/unique service-account passwords, patch to modern Windows Server
> (NetNTLMv1 off by default on 2019+), enable MFA, audit AD CS templates, and
> monitor with Sysmon + event logging.

## See also

- [Internal Network & AD](../scenarios/internal-network-ad.md) — this category's
  tools chained into a single end-to-end engagement walkthrough.
- [Post-Exploitation & Privilege Escalation](../post-exploitation/) — Mimikatz,
  credential dumping, WinPEAS, and general lateral movement.
- [Password Cracking & Hashing](../password-cracking/) — Hashcat/John for the
  NetNTLMv2, Kerberoast and AS-REP hashes captured above.
- [Network Traffic Analysis](../network-analysis/) — Wireshark/tcpdump to
  inspect the SMB/LDAP/Kerberos traffic these tools generate.

## References

- AD security blog: https://adsecurity.org/
- harmj0y's research: https://www.harmj0y.net/blog/
- Attacking AD (end-to-end): https://zer1t0.gitlab.io/posts/attacking_ad/
- Orange Cyberdefense AD pentest mind map:
  https://raw.githubusercontent.com/Orange-Cyberdefense/ocdmindmaps/main/img/pentest_ad_dark_2023_02.svg
- NTLM vs NetNTLM vs NetNTLMv2:
  https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4
