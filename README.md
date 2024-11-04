# VUT FIT - ISA 

### Autor: Adam Pap
### Login: xpapad11
### Dátum vytvorenia: 23.9.2023 
<p>&nbsp;</p>

### Popis programu
Jedná sa o program, ktorý vytvára štatistiku o využití sieťového prefixu z pohľadu množstva alokovaných IP adries.

Program pracuje v dvoch režimoch:
- režim spracovania .pcap súborov (```-r```)
    - výstupom tohto režimu je výpis tabuľky na STDOUT.
- režim odpočúvania DHCP komunikácie (```-i```)  
    - výstupom tohto režimu je priebežne aktualizovaná tabuľka, ktorá používateľa informuje o percentuálnom podiele alokovaných prefixov. Táto tabuľka je vytvorená za pomoci knižnice ```ncurses```.

Daná tabuľka má tieto stĺpce (platí pre oba režimy):

```IP-Prefix``` - stĺpec zobrazujúci používateľom zadané ip-prefixy aj sa maskami.

```Max-hosts``` - zobrazuje maximálny počet zariadení, ktoré sa do danej siete môžu pripojiť.

```Allocated addresses``` - zobrazuje počet ip adries ktoré boli využité v rámci daného prefixu

```Utilization``` - zobrazuje celklové využitie daného prefixu v percentách.

V prípade zaplnenia daného prefixu o viac ako 50% program informuje používateľa na STDOUT a danú udalosť zaloguje prostredníctvom syslog serveru.

V prípade potreby výpisu ako používať program, stačí skript spustiť s prepínačom ```-help```.

./dhcp-stats -help

Prípadne stačí spustiť program bez akýchkoľvek parametrov.
 
 ./dhcp-stats

Pre spustenie man stránok programu treba do terminálu zadať príkaz:

man -l dhcp-stats.1

### Obmedzenia/upozornenia pri používaní programu
V prípade spustenia programu v režime odpočúvania rozhrania (napr. eth0) sa očakáva spustenie programu pomocou príkazu ```sudo```.
Tiež je vhodné použiť príkaz  ```sudo``` v režime spracovania .pcap súborov aby sa vyhlo problémom s logovaním.

### Príklad spustenia programu
./dhcp-stats -r pcap_file_name.pcap 192.168.0.0/22 192.168.1.0/24

sudo ./dhcp-stats -i eth0 192.168.1.0/24 172.16.32.0/24 192.168.0.0/22 192.168.6.0/30

### Zoznam súborov
 - dhcp-stats.cpp
 - dhcp-stats.hpp
 - Makefile
 - README.md
 - manual.pdf
 - dhcp-stats.1

 ### Známe chyby
 V prípade spustenia programu s IP prefixom napr.: 192.168.0.0/32 program vracia pocet max-hosts -1, čo je samorejme zle. Dôvodom je to že program používa na spočítanie maximálneho počtu hostov vzroec 2^(32-n)-2, preto vzikla -1.