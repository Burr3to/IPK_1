### Problémy pri implementácii skenovania

Počas vývoja a testovania funkčnosti skenovania sa vyskytli nasledujúce problémy, ktoré sa zatiaľ nepodarilo úspešne vyriešiť:

**1. Problém so skenovaním localhostu:**

Pri skenovaní lokálnej adresy (localhost) sa zdá, že vytvorené TCP a UDP pakety sú úspešne
odosielané. Kontrolný súčet (checksum) je vypočítaný správne a jeho hodnotu je možné overiť aj
v nástroji Wireshark na rozhraní `lo` (loopback). Avšak, prichádzajúce odpovede sú v nástroji Wireshark
označené červenou farbou, čo indikuje chybu "BAD TCP" od Wireshark-u. Náš program momentálne nie je schopný tieto chybné
pakety zachytiť. Príčina tohto správania a dôvod, prečo sú odpovede označené ako chybné, zostáva mne nejasná.

**2. Obmedzenia testovania IPv6 a hostname skenovania:**

Celá implementácia a testovanie funkčnosti prebiehalo s využitím školského VPN pripojenia,
ktoré poskytovalo prístup k IPv6 sieti. Počas testovania sa ukázalo, že IPv6 pakety bolo možné
odosielať iba cez VPN rozhranie `tun0`, zatiaľ čo IPv4 pakety prechádzali cez štandardné sieťové
rozhranie `enp0s3`. Keďže od môjho poskytovateľa internetového pripojenia nemám pridelenú natívnu
IPv6 adresu, nebolo možné plnohodnotne otestovať skenovanie hostname pre IPv4 a IPv6 adresy súčasne
. Nie je preto známe, ako sa program bude správať v prostredí, kde je k dispozícii natívne IPv6 
pripojenie a ako bude prebiehať preklad a následné skenovanie hostname na obe IP verzie. Toto 
predstavuje potenciálnu oblasť pre ďalšie testovanie a overenie funkčnosti v reálnych podmienkach s
natívnou podporou IPv6.