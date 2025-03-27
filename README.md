# Dokumentácia k 1. úlohe do IPK 2024/2025

**Autor:** Jakub Fiľo - xfiloja00

---

## 1. Teória k projektu

TCP (Transmission Control Protocol) je protokol transportnej vrstvy. Charakteristickým znakom je nadviazanie spojenia pred prenosom dát a zabezpečenie spoľahlivého doručenia pomocou mechanizmov ako sekvenčné čísla, potvrdenia a opätovné odosielanie stratených paketov. TCP segmenty obsahujú hlavičku s rôznymi príznakmi, vrátane `SYN` (synchronize) pre iniciovanie spojenia a `RST` (reset) pre ukončenie alebo odmietnutie spojenia.

UDP (User Datagram Protocol) je nespolahlivý protokol transportnej vrstvy bez nadviazania spojenia. Poskytuje jednoduchý mechanizmus pre odosielanie datagramov s minimálnou réžiou, avšak bez záruk doručenia, poradia alebo absencie duplicitných paketov. V prípade nedostupnosti cieľového UDP portu môže odosielateľ obdržať ICMP správu o chybe. Pre IPv4 je to správa typu 3 (Destination Unreachable), kód 3 (Port Unreachable). Pre IPv6 je to správa typu 1 (Destination Unreachable), kód 4 (Port Unreachable).

IPv4/IPv6 sú protokoly sieťovej vrstvy, ktoré zabezpečujú logické adresovanie zariadení v sieti a smerovanie dátových paketov medzi nimi. Každý protokol má špecifickú štruktúru hlavičky obsahujúcu adresy zdroja a cieľa, ako aj ďalšie riadiace informácie.

Raw sockety sú nízkoúrovňové rozhrania, ktoré umožňujú programom priamy prístup k sieťovej vrstve. Umožňujú vytvárať a odosielať pakety s vlastnými hlavičkami (vrátane IP, TCP a UDP) a prijímať všetky prichádzajúce pakety na danom sieťovom rozhraní.

---

## 2. Zaujímavá časť kódu

Program využíva asynchrónne programovanie na výrazné zrýchlenie skenovania. Pre každú cieľovú IP adresu sa spúšťajú TCP a UDP skenovania ako nezávislé úlohy (`Task`). Tieto úlohy bežia paralelne, čo znamená, že program nemusí čakať na dokončenie jedného skenovania, kým začne ďalšie. Všetky spustené skenovacie úlohy sa evidujú v zozname `scanTasks`. Kľúčové slovo `await` v spojení s `Task.WhenAll()` zabezpečuje, že hlavný program počká na dokončenie všetkých týchto súbežne bežiacich skenovaní predtým, ako sa ukončí. Tento prístup efektívne využíva systémové prostriedky a minimalizuje čas potrebný na kompletné preskenovanie zadaných cieľov a portov.

```csharp
var scanTasks = new List<Task>();
scanTasks.Add(tcpScanner.ScanTcpAsync());
scanTasks.Add(udpScanner.ScanUdpAsync());
await Task.WhenAll(scanTasks);
```
## 3. Testovanie s nmap

Táto časť dokumentácie opisuje proces testovania vyvinutého L4 skenera. Cieľom testovania bolo overiť správnu funkčnosť aplikácie pri skenovaní TCP a UDP portov na IPv4 a IPv6 adresách a porovnať jej výstupy s nástrojom nmap.

#### Operačné prostredie

- **Operačný systém:**  
  Linux Ubuntu 24.04 (OVA obraz)

- **Testovaný cieľ:**  
  `scanme.nmap.org`  
  - **IPv4 adresa:** `45.33.32.156`  
  - **IPv6 adresa:** `2600:3c01::f03c:91ff:fe18:bb2f`

- **Sieťové rozhrania:**  
  - `enp0s3`: Používané pre testovanie IPv4 komunikácie.  
  - `tun0`: Používané pre testovanie IPv6 komunikácie.

- **Porovnávací nástroj:**  
  nmap (verzia dostupná v Ubuntu 24)

## TCP skenovanie IPv4

**Čo sa testovalo:**  
TCP SYN skenovanie špecifických portov na IPv4 adrese.

**Prečo sa to testovalo:**  
Overenie základnej funkčnosti TCP skenovania pre IPv4.

**Ako sa to testovalo:**  
Spustením nášho skenera a nástroja nmap na IPv4 adresu [scanme.nmap.org](http://scanme.nmap.org) (45.33.32.156) pre porty 19 a 22.

**Testovacie prostredie:**  
Linux Ubuntu 24.04, rozhranie enp0s3.

### Input (nmap):
sudo nmap -sS -p 19,22 45.33.32.156
### Input (nás skener):
enp0s3 -t 19,22 45.33.32.156
### Očákavaný výstup
PORT    STATE   SERVICE
19/tcp  closed  chargen
22/tcp  open    ssh
### Skutočný výstup
45.33.32.156 22 tcp open
45.33.32.156 19 tcp closed

## TCP skenovanie IPv6

**Čo sa testovalo:**
TCP SYN skenovanie špecifických portov na IPv6 adrese.

**Prečo sa to testovalo:**
Overenie funkčnosti TCP skenovania pre IPv6.

**Ako sa to testovalo:**
Spustením nášho skenera a nástroja nmap na IPv6 adresu scanme.nmap.org (2600:3c01::f03c:91ff:fe18:bb2f) pre porty 19 a 22.

**Testovacie prostredie:**
Linux Ubuntu 24.04, rozhranie tun0.

### Input (nmap):
sudo nmap -6 -sS -p 19,22 2600:3c01::f03c:91ff:fe18:bb2f
### Input (nás skener):
tun0 -t 19,22 2600:3c01::f03c:91ff:fe18:bb2f
### Očakávaný výstup
PORT   STATE    SERVICE
19/tcp closed   chargen
22/tcp open     ssh
### Skutočný výstup
2600:3c01::f03c:91ff:fe18:bb2f 22 tcp open
2600:3c01::f03c:91ff:fe18:bb2f 19 tcp closed

## UDP skenovanie IPv4

**Čo sa testovalo:**
UDP skenovanie špecifických portov na IPv4 adrese.

**Prečo sa to testovalo:**
Overenie základnej funkčnosti UDP skenovania pre IPv4.

**Ako sa to testovalo:**
Spustením nášho skenera a nástroja nmap na IPv4 adresu scanme.nmap.org (45.33.32.156) pre porty 53 a 123.

**Testovacie prostredie:**
Linux Ubuntu 24.04, rozhranie enp0s3.

### Input (nmap):
sudo nmap -sU -p 53,123 45.33.32.156
### Input (nás skener):
enp0s3 -u 53,123 45.33.32.156
### Očakávaný výstup
PORT    STATE         SERVICE
53/udp  open|filtered domain
123/udp open          ntp
### Skutočný výstup
45.33.32.156 123 udp open
45.33.32.156 53 udp open|filtered

## UDP skenovanie IPv6

**Čo sa testovalo:**
UDP skenovanie špecifických portov na IPv6 adrese.

**Prečo sa to testovalo:**
Overenie funkčnosti UDP skenovania pre IPv6.

**Ako sa to testovalo:**
Spustením nášho skenera a nástroja nmap na IPv6 adresu scanme.nmap.org (2600:3c01::f03c:91ff:fe18:bb2f) pre porty 53 a 123.

**Testovacie prostredie:**
Linux Ubuntu 24.04, rozhranie tun0.

### Input (nmap):
sudo nmap -6 -sU -p 53,123 2600:3c01::f03c:91ff:fe18:bb2f
### Input (nás skener):
tun0 -u 53,123 2600:3c01::f03c:91ff:fe18:bb2f
### Očakávaný výstup
PORT    STATE         SERVICE
53/udp  open|filtered domain
123/udp open          ntp
### Skutočný výstup
2600:3c01::f03c:91ff:fe18:bb2f 123 udp open
2600:3c01::f03c:91ff:fe18:bb2f 53 udp open|filtered

## Kombinované TCP a UDP skenovanie IPv4

**Čo sa testovalo:**
Skenovanie TCP a UDP portov súčasne na IPv4 adrese.

**Prečo sa to testovalo:**
Overenie schopnosti skenera spracovať viacero protokolov naraz.

**Ako sa to testovalo:**
Spustením nášho skenera a nástroja nmap na IPv4 adresu scanme.nmap.org (45.33.32.156) pre TCP porty 19, 22 a UDP porty 53, 123.

**Testovacie prostredie:**
Linux Ubuntu 24.04, rozhranie enp0s3.

### Input (nmap):
sudo nmap -sS -sU -p T:19,22,U:53,123 45.33.32.156
### Input (nás skener):
enp0s3 -t 19,22 -u 53,123 45.33.32.156
### Očakávaný výstup
PORT    STATE         SERVICE
19/tcp  closed        chargen
22/tcp  open          ssh
53/udp  open|filtered domain
123/udp open          ntp
### Skutočný výstup
45.33.32.156 22 tcp open
45.33.32.156 19 tcp closed
45.33.32.156 123 udp open
45.33.32.156 53 udp open|filtered

## Kombinované TCP a UDP skenovanie IPv6

**Čo sa testovalo:**
Skenovanie TCP a UDP portov súčasne na IPv6 adrese.

**Prečo sa to testovalo:**
Overenie schopnosti skenera spracovať viacero protokolov naraz pre IPv6.

**Ako sa to testovalo:**
Spustením nášho skenera a nástroja nmap na IPv6 adresu scanme.nmap.org (2600:3c01::f03c:91ff:fe18:bb2f) pre TCP porty 19, 22 a UDP porty 53, 123.

**Testovacie prostredie:**
Linux Ubuntu 24.04, rozhranie tun0.

### Input (nmap):
sudo nmap -6 -sS -sU -p T:19,22,U:53,123 2600:3c01::f03c:91ff:fe18:bb2f
### Input (nás skener):
tun0 -t 19,22 -u 53,123 2600:3c01::f03c:91ff:fe18:bb2f
### Očakávaný výstup
PORT    STATE         SERVICE
19/tcp  closed        chargen
22/tcp  open          ssh
53/udp  open|filtered domain
123/udp open          ntp

### Skutočný výstup

2600:3c01::f03c:91ff:fe18:bb2f 22 tcp open
2600:3c01::f03c:91ff:fe18:bb2f 19 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 123 udp open
2600:3c01::f03c:91ff:fe18:bb2f 53 udp open|filtered

## Skenovanie hostname (IPv4 a IPv6)

**Čo sa testovalo:**
Skenovanie hostname scanme.nmap.org, ktoré by malo preložiť na IPv4 a IPv6 adresy.

**Prečo sa to testovalo:**
Overenie schopnosti skenera preložiť hostname na IP adresy a skenovať obe verzie.

**Ako sa to testovalo:**
Spustením nášho skenera a nástroja nmap na hostname scanme.nmap.org pre TCP porty 19 a 22 a UDP porty 53 a 123. Testovalo sa s explicitným špecifikovaním rozhraní pre IPv4 (enp0s3) a IPv6 (tun0).

**Testovacie prostredie:**
Linux Ubuntu 24.04, rozhrania enp0s3 a tun0.

### Input (náš skener - IPv4):

enp0s3 -t 19,22 scanme.nmap.org

### Input (náš skener - IPv6):

tun0 -t 19,22 scanme.nmap.org

### Input (nmap - IPv4):

sudo nmap -sS -p 19,22 scanme.nmap.org

### Input (nmap - IPv6):

sudo nmap -6 -sS -p 19,22 scanme.nmap.org

### Očakávaný výstup (IPv4)

PORT   STATE    SERVICE
19/tcp closed   chargen
22/tcp open     ssh

### Očakávaný výstup (IPv6)

PORT   STATE    SERVICE
19/tcp closed   chargen
22/tcp open     ssh

### Skutočný výstup (náš skener - IPv4)

45.33.32.156 22 tcp open
45.33.32.156 19 tcp closed

### Skutočný výstup (náš skener - IPv6)

2600:3c01::f03c:91ff:fe18:bb2f 22 tcp open
2600:3c01::f03c:91ff:fe18:bb2f 19 tcp closed

### Skutočný výstup (nmap - IPv4)

PORT   STATE    SERVICE
19/tcp closed   chargen
22/tcp open     ssh

### Skutočný výstup (nmap - IPv6)

PORT   STATE    SERVICE
19/tcp closed   chargen
22/tcp open     ssh

### 4. Bibliografia

Cisco Networking Academy. IPv4 vs IPv6. Online. Available from: https://www.networkacademy.io/ccna/ipv6/ipv4-vs-ipv6 [Accessed 27 March 2025].

inc0x0. TCP/IP Packets Introduction - Part 3: Manually Create and Send Raw TCP/IP Packets. Online. Available from: https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/ [Accessed 27 March 2025].

Wikipedia contributors. Transmission Control Protocol. Online. Available from: https://cs.wikipedia.org/wiki/Transmission_Control_Protocol [Accessed 27 March 2025].

Wikipedia contributors. User Datagram Protocol. Online. Available from: https://cs.wikipedia.org/wiki/User_Datagram_Protocol [Accessed 27 March 2025].

Microsoft. .NET API Browser. Online. Available from: https://learn.microsoft.com/en-us/dotnet/api/system.net?view=net-9.0 [Accessed 27 March 2025].

Nmap Project. scanme.nmap.org. Online. Available from: http://scanme.nmap.org/ [Accessed 27 March 2025].