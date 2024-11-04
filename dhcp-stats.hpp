/*
 * ISA 2023 PROJECT - DHCP
 *
 * File: dhcp-stats.hpp
 * 
 * Author: Adam Pap, xpapad11
*/
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <regex>
#include <cctype>
#include <cmath>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <ncurses.h>
#include <signal.h>
#include <syslog.h>
#include <set>

using namespace std;

enum // Chybove kody
{
    PARAM_HIGH_E = 1, // Velky pocet parametrov
    PARAM_LOW_E,      // Maly pocet parametrov
    PARAM_E,          // Neznamy/zly parameter
    PCAP_E,           // Chyba viazuca sa na odchyt/odpocuvanie packetov
    PACKET_PROC_E     // Chyba pri spracovani packetu
};

struct dhcp_packet
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    struct in_addr ciaddr;
    struct in_addr yiaddr;
    struct in_addr siaddr;
    struct in_addr giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t options_var;
};

vector<string> ip_prefix; // vektor pre ukladanie IP prefixov z prikazovej riadky

struct subnet_stats
{
    uint64_t max_hosts;
    uint64_t allocated_addrs;
    float utilization;
    int logged;
    string yiaddr;
};
map<string, subnet_stats> stats; // mapa pre ukladanie statistik DHCP

pcap_if_t *alldevs; //kvoli uvolnovaniu adries z pcap_findalldevs to je tu

map<string, set<string>> allocated_addresses; // mapa pre ukladanie pridelenej IP adresy