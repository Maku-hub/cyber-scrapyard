# Operating System Security

Reference notes on the internals and security-relevant administration of the
major operating systems. These pages collect useful commands and mechanisms —
presented as administrative, diagnostic, and blue-team knowledge — so you
understand how each platform works and where its security boundaries sit.

> ⚠️ **For authorized and educational use only.** Commands here are for systems
> you own or administer, and for authorized lab work. Understanding how a
> mechanism can be abused is a defensive skill; use it accordingly.

## Pages

| Page | Summary |
| --- | --- |
| [Windows](windows.md) | Admin, diagnostic and recon commands: netsh, systeminfo, routing, BitLocker, NTDLL notes |
| [Linux](linux.md) | Networking, enumeration, permissions and privilege-escalation reference commands |
| [macOS](macos.md) | SIP, Gatekeeper, XProtect, TCC, notarization and Keychain mechanisms, with inspection commands |
| [Android](android.md) | Boot chain, SELinux/sandbox/encryption mechanisms, root & Magisk |
| [iOS](ios.md) | Boot chain, Secure Enclave, sandbox, Data Protection, jailbreak concepts |
| [Cloud](cloud.md) | Cloud security learning pointers and CloudGoat |

See also: [Post-Exploitation & Privilege Escalation](../post-exploitation/),
[Defensive Security & Blue Team](../defense-blueteam/), and
[Containers & Cloud Security](../containers-cloud/).
