# Sprzęt i narzędzia

Zbiór sprzętu i oprogramowania przydatnego w cyberbezpieczeństwie. Niżej, w sekcji [Koszt i tańsze odpowiedniki DIY](#koszt-i-ta%C5%84sze-odpowiedniki-diy), opis tego, co da się odtworzyć taniej własnymi siłami.

## Uwierzytelnianie i sprzętowe klucze bezpieczeństwa

* **YubiKey / Security Key NFC (Yubico)** — klucze sprzętowe najwyższej klasy do MFA, logowania bez hasła, SSH, FIDO2.

## Narzędzia bezprzewodowe (Wi-Fi)

* **Alfa AWUS036ACHM / AWUS1900 / AWUS036AXML** — mocne, dobrze wspierane karty do trybu monitor i wstrzykiwania pakietów.
* **Wi-Fi Pineapple** — wyspecjalizowane urządzenie do ataków na Wi-Fi: rogue AP, man-in-the-middle, szkolenia.

## Narzędzia USB

* **Bash Bunny** — wielopayloadowa platforma ataków przez USB (wstrzykiwanie klawiatury, spoofing sieci, kradzież poświadczeń itd.).
* **Rubber Ducky** — klasyczne urządzenie udające „klawiaturę USB"; bardzo proste i skuteczne.
* **O.MG Cable** — uzbrojony kabel zdolny do dostarczania payloadów, zdalnego wyzwalania i ataków HID.
* **USBKill V4** — urządzenie niszczące, które przepala linie zasilania USB (atak fizyczny — nieodwracalnie uszkadza sprzęt).

## Implanty sieciowe i urządzenia improwizowane

* **Packet Squirrel** — inline'owy implant sieciowy do przechwytywania pakietów i zdalnego dostępu.
* **Plunder Bug** — kompaktowy tap/sniffer sieciowy.
* **Shark Jack** — szybkie narzędzie do rozpoznania sieci oparte na payloadach.
* **Screen Crab** — implant do przechwytywania obrazu (zrzuty ekranu przez sieć).

## Radio, SDR i badania RF

* **RTL-SDR V4** — budżetowe radio programowalne; świetne do nauki podstaw SDR.
* **HackRF One** — SDR średniej klasy z TX/RX; idealny do badań nad bezpieczeństwem bezprzewodowym.
* **KrakenSDR** — wielokanałowy SDR do zaawansowanej analizy RF i namierzania kierunku (direction finding).

## RFID, NFC i kontrola dostępu

* **Proxmark 3 RDV4.01** — najlepsze narzędzie do badań nad RFID: klonowanie, łamanie, analiza.
* **Chameleon Ultra** — wydajny emulator/kloner NFC do testów i badań.
* **Ultimate Magic Card (Gen4)** — emulator kart HF z zaawansowanymi funkcjami.
* **RFID Field Detector** — proste narzędzie do wizualizacji obecności pola RFID.

## Multitoole i pozostały sprzęt

* **Flipper Zero** — wieloprotokołowa „zabawka" hakerska: sub-GHz, RFID, NFC, IR, GPIO; ogromny ekosystem.
* **PandwaRF** — narzędzie sub-GHz do replay i analizy sygnałów RF.
* **ChipWhisperer** — platforma do hardware hackingu i analizy side-channel.

## Oprogramowanie

* **Burp Suite Professional (PortSwigger Pro)** — standardowy w branży zestaw do pentestów aplikacji webowych.
* **Binary Ninja** — zaawansowana platforma do reverse engineeringu (czytelny interfejs, mocne skryptowanie).
* **Shodan** — „wyszukiwarka internetu rzeczy"; świetna do rozpoznania i mapowania wystawionych systemów.

## Koszt i tańsze odpowiedniki DIY

Wiele z wymienionych narzędzi wygląda na drogie, a w praktyce **sporą ich część da się odtworzyć dużo taniej** z użyciem otwartego sprzętu, mikrokontrolerów lub komponentów DIY.
Na przykład:

* **Rubber Ducky** można zbudować na prostej płytce **ATmega32U4 (np. CJMCU / Pro Micro)** z własnym firmware do wstrzykiwania HID — [jak tutaj](./BadUSB/badusb.ino).
* **Kartę do pentestów Wi-Fi** często można zastąpić tanią kartą na tym samym chipsecie.
* Nawet narzędzia takie jak **Bash Bunny** czy **O.MG Cable** mają częściowe odpowiedniki DIY oparte na płytkach ESP8266/ESP32 i otwartych frameworkach payloadów.

Tak więc **uproszczone wersje tych narzędzi da się zbudować za ułamek ceny** — do nauki i eksperymentów to zwykle w zupełności wystarcza.

### Dlaczego oficjalne, komercyjne narzędzia są droższe?

Mimo że wiele z tych urządzeń ma tanie odpowiedniki DIY, wersje oficjalne kosztują więcej, bo oferują:

* **Wyższą niezawodność** — działają stabilnie i są zbudowane na lata.
* **Lepszy firmware i funkcje** — zoptymalizowane silniki payloadów, stabilne aktualizacje, dopracowane oprogramowanie.
* **Łatwość użycia** — brak konfiguracji, kodowania czy grzebania w sprzęcie; działają od razu.
* **Wsparcie i aktualizacje** — regularne usprawnienia, poprawki błędów, dokumentacja, zasoby społeczności.
* **Zaufanie zawodowe** — szeroko stosowane w branży, więc wyniki są przewidywalne i powtarzalne.

W skrócie: **płacisz za stabilność, wygodę i jakość klasy profesjonalnej**, nie tylko za sam sprzęt.
