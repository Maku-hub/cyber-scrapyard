# Cybersecurity Toolbox

A curated reference of the most useful **tools, services and techniques** in cybersecurity — each with a short description, a link, and a practical usage example.

The goal is a single, well-organized starting point for security practitioners and learners: *what exists, what it's for, and how to actually use it.* Entries lean practical over exhaustive — enough to know when to reach for a tool and how to begin.

> ⚠️ **For authorized and educational use only.** Everything here is meant for legal security research, CTFs, home labs, and work you are explicitly permitted to perform. Use it only against systems you own or have written permission to test.

## How this repo is organized

Every level is an index that leads to the next:

- this `README.md` → links to each **category**
- each category's `README.md` → links to individual **tool/topic** pages
- each tool page → description, link, install, and usage examples

Each tool page follows the same template (see [`TEMPLATE.md`](TEMPLATE.md)) so entries stay consistent and easy to scan.

## Categories

> 🧭 **New here? Start with [Example Scenarios](scenarios/)** — end-to-end
> walkthroughs that chain these tools for common engagements (external recon, web
> app, internal AD, Linux server, Wi-Fi, containers, malware triage).

### Offensive

| Category | What's inside |
| --- | --- |
| [Methodology & Frameworks](methodology/) | Cyber Kill Chain, MITRE ATT&CK, recon workflow, sample walkthroughs |
| [Reconnaissance & Scanning](recon-scanning/) | Nmap, Masscan, RustScan, subdomain & port discovery |
| [OSINT](osint/) | Shodan, Maltego, theHarvester, SpiderFoot, certificate transparency |
| [Web Application Security](web-app-security/) | Burp Suite, OWASP ZAP, sqlmap, ffuf, Nuclei, wpscan |
| [Mobile App Security](mobile-app-security/) | MobSF, jadx, apktool, objection, Drozer, Frida |
| [Exploitation & C2](exploitation-c2/) | Metasploit, msfvenom, Sliver, Empire, Social-Engineer Toolkit |
| [Post-Exploitation & Privilege Escalation](post-exploitation/) | Mimikatz, LinPEAS/WinPEAS, GTFOBins, LOLBAS, Impacket |
| [Active Directory](active-directory/) | Responder, NetExec/CrackMapExec, BloodHound, Evil-WinRM, Kerberos attacks |
| [Wi-Fi & Wireless](wifi-wireless/) | Aircrack-ng, Wifite, Kismet, evil twin, WPA attacks |
| [Social Engineering & Phishing](social-engineering-phishing/) | GoPhish, evilginx2, SET, Zphisher, awareness & defense |
| [Password Cracking & Hashing](password-cracking/) | Hashcat, John the Ripper, Hydra, wordlists |
| [Cryptography](cryptography/) | OpenSSL, GPG, age, CyberChef, PKI & hashing concepts |

### Defensive & Analysis

| Category | What's inside |
| --- | --- |
| [Network Traffic Analysis](network-analysis/) | Wireshark, tcpdump, Scapy, tshark, Ettercap |
| [Reverse Engineering & Malware Analysis](reverse-engineering-malware/) | Ghidra, IDA, x64dbg, YARA, ANY.RUN, sandboxes |
| [Digital Forensics & Incident Response](forensics-ir/) | Autopsy, Volatility, Sleuth Kit, FTK Imager |
| [Defensive Security & Blue Team](defense-blueteam/) | Snort/Suricata, Wazuh, Sysmon, ModSecurity, EDR concepts |
| [Automated Security Scanners](vulnerability-scanners/) | OpenVAS, Nessus Essentials, Trivy, Grype, Lynis, OpenSCAP, Semgrep, secret scanners |
| [Containers & Cloud Security](containers-cloud/) | Docker security, Trivy, kube-bench, Kubescape, ScoutSuite, CloudGoat |

### Systems, Hardware & Learning

| Category | What's inside |
| --- | --- |
| [Operating System Security](os-security/) | Windows, Linux, Android, iOS, cloud internals & hardening |
| [Hardware & Physical Tools](hardware/) | Flipper Zero, SDR, RFID/NFC, Wi-Fi adapters, BadUSB, DIY equivalents |
| [Developer Tools & Productivity](dev-tools/) | VS Code, tmux, terminal & workflow tooling |
| [Learning Resources](learning-resources/) | Books, certifications, platforms, creators, news, cheat sheets |

## Contributing / notes

This is a personal, evolving knowledge base. Entries are added and refined over time; missing pages are stubs waiting to be filled. Suggestions and corrections are welcome via issues or pull requests.
