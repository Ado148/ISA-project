/*
 * ISA 2023 PROJECT - DHCP
 *
 * File: dhcp-stats.cpp
 *
 * Author: Adam Pap, xpapad11
 */
#include "dhcp-stats.hpp"

void help_msg()
{
    cout << "Spustenie programu: ./dhcp-stats [-help] [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]" << endl;
    cout << "Parametre:" << endl;
    cout << "  -r file.pcap  Statistika bude vytvorena z pcap suborov" << endl;
    cout << "  -i interface  Statistika bude vytvorena z rozhrania na ktorom program pocuva" << endl;
    cout << "  -help         Zobrazi napovedu" << endl;
    cout << "IP-prefix treba zadavat v spravnom formate, v pripade ze zadate nevalidny ip-prefix program nemusi spravne fungovat" << endl;
}

void Signal_handler(int handler)
{
    (void)handler;
    pcap_freealldevs(alldevs);
    endwin();
    exit(0);
}

int is_validIP(string IP_ADD) // funckia na kontrolu korektnosti IP adresy, nekontroluje ale prefix
{
    int check = 0;
    unsigned char buff[sizeof(struct in_addr)];
    string mask;
    string ip_without_mask;

    size_t slash_pos = IP_ADD.find("/");
    if (slash_pos != string::npos) // ak sa v adrese nachadza lomitko tak ho odstran
    {
        ip_without_mask = IP_ADD.substr(0, slash_pos);
        mask = IP_ADD.substr(slash_pos + 1);
    }
    else
    {
        return false;
    }

    try // handlovanie vynimky ak je maska nevalidna
    {
        stoi(mask);
    }
    catch (exception &PARAM_E)
    {
        return false;
    }

    if (stoi(mask) > 32 || stoi(mask) < 0) // kontrola masky
    {
        return false;
    }

    check = inet_pton(AF_INET, ip_without_mask.c_str(), buff);
    if (check <= 0)
    {
        if (check == 0)
        {
            return false;
        }
        else
        {
            perror("inet_pton");
            return false;
        }
    }
    return true;
}

uint64_t max_host_count(const string &ip)
{
    size_t position = ip.find("/"); // najdi kde sa nachadza lomitko kvoli maske
    if (position == string::npos)
    {
        return PACKET_PROC_E;
    }

    uint64_t prefix_len = stoi(ip.substr(position + 1)); // ziskaj prefix za "/"
    return pow(2, 32 - prefix_len) - 2;                  // vypocitaj max. pocet hostov
}

int allocated_addresses_count(const string &prefix, char *yiaddr)
{
    size_t position = prefix.find("/"); // najdi kde sa nachadza lomitko kvoli maske
    if (position == string::npos)
    {
        exit(PACKET_PROC_E);
    }

    string ip = prefix.substr(0, position);
    string mask = prefix.substr(position + 1);

    struct in_addr ip_addr;
    struct in_addr yiaddr_addr;

    inet_aton(ip.c_str(), &ip_addr); // preloz IP adresu od uzivatela do citatelnej podoby
    inet_aton(yiaddr, &yiaddr_addr); // preloz yiaddr do citatelnej podoby

    int cidr = stoi(mask);
    uint32_t final_mask = (~0U) << (32 - cidr); // ~0U - unsigned int s vsetkymi bitmi nastavenymi na 1 co je vlastne -1 pre signed int

    // vyppocitaj broadcast adresu
    struct in_addr broadcast_addr;
    struct in_addr network_addr;
    broadcast_addr.s_addr = (ip_addr.s_addr & htonl(final_mask)) | ~htonl(final_mask); // tilda len flipne biti masky na jednotky a vypocita broadcast adresu
    network_addr.s_addr = (ip_addr.s_addr & htonl(final_mask));                        // vypocitaj network adresu

    // pozri ci adresa nie je nahodou broadcast adresa
    if ((yiaddr_addr.s_addr != broadcast_addr.s_addr) && (yiaddr_addr.s_addr != network_addr.s_addr))
    {
        // urob bitovy sucin s ip adresou a maskou a potom porovnaj ci vysledok tychto bit. sucinov je zhodny
        ip_addr.s_addr = ip_addr.s_addr & htonl(final_mask);
        yiaddr_addr.s_addr = yiaddr_addr.s_addr & htonl(final_mask);

        string yiaddr_str(yiaddr);
        if ((ip_addr.s_addr == yiaddr_addr.s_addr) && yiaddr_str != "0.0.0.0" && allocated_addresses[prefix].find(yiaddr_str) == allocated_addresses[prefix].end())
        {
            allocated_addresses[prefix].insert(yiaddr);
            return 1;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    return 0;
}

void print_ncurses()
{
    clear();
    mvprintw(0, 0, "IP-Prefix");
    mvprintw(0, 20, "Max-hosts");
    mvprintw(0, 40, "Allocated addresses");
    mvprintw(0, 70, "Utilization");
}

void print_stats()
{
    for (auto prefix : ip_prefix)
    {
        int hosts = 0;
        if (stats.find(prefix) == stats.end()) // ak sa IP adresa od uzivatela este nenachadza v mape, pridaj ju
        {
            hosts = max_host_count(prefix); // zisti maximalny pocet hostov v danej podsieti
            subnet_stats new_subnet;
            new_subnet.max_hosts = hosts;
            new_subnet.allocated_addrs = 0;
            new_subnet.utilization = 0;
            stats.insert(pair<string, subnet_stats>(prefix, new_subnet));
        }

        int row = 1;
        for (auto pair : stats)
        {
            const std::string &subnet_prefix = pair.first;
            const subnet_stats &subnet_stats = pair.second;

            mvprintw(row, 0, subnet_prefix.c_str());
            mvprintw(row, 20, "%ld", subnet_stats.max_hosts);
            mvprintw(row, 40, "%ld", subnet_stats.allocated_addrs);
            mvprintw(row, 70, "%.2f%%", subnet_stats.utilization);
            if (subnet_stats.utilization > 50)
            {
                row++;
                mvprintw(row, 0, "prefix  %s exceeded 50%% of allocations", subnet_prefix.c_str());
            }
            row++;
            refresh();
        }
        napms(10);
    }
}

void packetProcessing(u_char *file_or_interface, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    u_char *dhcp_option_53;
    uint64_t hosts = 0;
    int is_here = 0; // premenna ktora zistuje ci je v options tag 53 z ktoreho nasledne ziskame DHCP msg type
    int logged = 0;
    int size_of_header = 0;
    int total_pkt_length = pkthdr->len; // ziskaj celkovu dlzku packetu
    /*------------------------------------------------------------------------------------------INSPIROVANE - http://yuba.stanford.edu/~casado/pcap/section4.html ---------------------------------------------------------------------------*/
    struct ether_header *eth_header = (struct ether_header *)packet; // ziskaj ethernet hlavicku

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) // ak nie je IP hlavicka tak skonci
    {
        return;
    }
    struct iphdr *ip_header = (struct iphdr *)(packet + ETHER_HDR_LEN); // ziskaj IP hlavicku, a odstran ethernet hlavicku
    if (ip_header->protocol != IPPROTO_UDP)                             // ak nie je UDP hlavicka tak skonci
    {
        return;
    }
    struct udphdr *udp_header = (struct udphdr *)(packet + ETHER_HDR_LEN + (ip_header->ihl * 4)); // ziskaj UDP hlavicku, a odstran IP hlavicku
    if (ntohs(udp_header->source) == 67 || ntohs(udp_header->source) == 68)                       // spracuj DHCP pakety len
    {
        size_of_header = sizeof(struct ether_header) + (ip_header->ihl * 4) + sizeof(udp_header); // ziskaj velkost hlavicky
    }
    else
    {
        return;
    }
    /*------------------------------------------------------------------------------------------INSPIROVANE - http://yuba.stanford.edu/~casado/pcap/section4.html ---------------------------------------------------------------------------*/
    u_char *dhcp_header_start = (u_char *)(packet + size_of_header);
    u_char *dhcp_options = dhcp_header_start + 240;
    int dhcp_option_length = total_pkt_length - size_of_header - 240; // ziskaj dlzku DHCP option fieldu ktora je variable

    for (int i = 0; i < dhcp_option_length; i++)
    {
        if (dhcp_options[i] == 53)
        {
            dhcp_option_53 = dhcp_options + i - 1; // ziskaj DHCP option 53 (jeho zaciatok)
            is_here = 1;
            break;
        }
    }

    if (is_here == 0)
    {
        return;
    }
    else if (is_here == 1)
    {
        // u_char dhcp_message_type;
        for (int j = 0; j < dhcp_option_53[1]; j++)
        {
            if (dhcp_option_53[2 + j] == 5)
            {
                dhcp_option_53 = dhcp_option_53 + j;
                break;
            }
        }
    }

    switch (dhcp_option_53[2])
    {
    case 5: // DHCPACK
        struct dhcp_packet *dhcp_header = (struct dhcp_packet *)(packet + size_of_header);
        char *ip_address = inet_ntoa(dhcp_header->yiaddr);
        for (const auto &prefix : ip_prefix) // iteruj cez uzivatelom zadane ip prefixy
        {
            hosts = max_host_count(prefix); // zisti maximalny pocet hostov v danej podsieti
            int allocated_adresses_count = 0;

            allocated_adresses_count = allocated_addresses_count(prefix, ip_address); // pridaj alokovanu adresu

            if (stats.find(prefix) == stats.end()) // ak sa IP adresa od uzivatela este nenachadza v mape, pridaj ju
            {
                subnet_stats new_subnet;
                new_subnet.allocated_addrs = 0;
                new_subnet.max_hosts = hosts;
                if (allocated_adresses_count)
                {
                    new_subnet.allocated_addrs += allocated_adresses_count;
                    new_subnet.utilization = (float)new_subnet.allocated_addrs / (float)new_subnet.max_hosts * 100;
                    if (new_subnet.utilization > 50 && new_subnet.logged != 2)
                    {
                        new_subnet.logged = 1;
                        logged = 1;
                    }
                    // new_subnet.yiaddr = ip_address;
                }
                else
                {
                    new_subnet.allocated_addrs = 0;
                    new_subnet.utilization = 0;
                }
                stats.insert(pair<string, subnet_stats>(prefix, new_subnet));
            }
            else // ak sa IP adresa uz nachadza v mape len ju updatni
            {
                subnet_stats &subnet = stats[prefix];
                if (allocated_adresses_count)
                {
                    subnet.allocated_addrs = allocated_addresses[prefix].size();
                    subnet.utilization = (float)subnet.allocated_addrs / (float)subnet.max_hosts * 100;
                    if (subnet.utilization > 50 && subnet.logged != 2)
                    {
                        subnet.logged = 1;
                        logged = 1;
                    }
                }
            }

            if (logged)
            {
                for (const auto &pair : stats)
                {
                    const subnet_stats &subnet_stats = pair.second;
                    if (subnet_stats.utilization > 50 && stats[prefix].logged == 1)
                    {
                        logged = 0;
                        setlogmask(LOG_UPTO(LOG_NOTICE)); // nastav prioritu logovania aspon na LOG_NOTICE a vyssie
                        openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
                        syslog(LOG_NOTICE, "prefix %s exceeded 50%% of allocations .", prefix.c_str());
                        closelog();
                        stats[prefix].logged = 2; // aby sa to nezalogovalo viac krat
                    }
                }
            }
        } // for
        break;
    } // switch

    if (*file_or_interface == 0) // ak sa jedna o interface tak vypisuj statistiky na obrazovku in real time
    {
        print_stats();
    }
}

int main(int argc, char *argv[])
{
    string pcap_file;
    string interface_name;
    bool one_stat_src = false; // premenna krtora zabezpecuje ze user nezada jak interface tak aj subor naraz
    int file_or_interface = 0; // premenna ktora zistuje ci user zadal subor 1 - subor, 0 - interface

    if (argc <= 1)
    {
        help_msg();
        return 0;
    }

    for (int i = 1; i < argc; ++i) // iteruj cez argumenty programu
    {
        string arg = argv[i];

        if (arg == "-help")
        {
            help_msg();
            return 0;
        }
        else if (arg == "-r" && one_stat_src == 0)
        {
            if (i + 1 < argc) // over ze existuje dalsi argument
            {
                pcap_file = argv[++i]; // uloz nazov suboru
            }
            else
            {
                cerr << "Parameter -r vyzaduje uvedenie nazvu suboru: ./dhcp-stats [-r <filename>]" << endl;
                return PARAM_LOW_E;
            }
            one_stat_src = 1;
            file_or_interface = 1;
        }
        else if (arg == "-i" && one_stat_src == 0)
        {
            if (i + 1 < argc)
            {
                interface_name = argv[++i];
            }
            else
            {
                cerr << "Parameter -i vyzaduje uvedenie nazvu rozhrania: ./dhcp-stats [-i <interface-name>]" << endl;
                return PARAM_LOW_E;
            }
            one_stat_src = 1;
            file_or_interface = 0;
        }
        else if (one_stat_src == 1 && (arg == "-i" || arg == "-r"))
        {
            cerr << "Nemozno zadat viacero zdrojov statistiky naraz: ./dhcp-stats [-r <filename>] [-i <interface-name>]" << endl;
            return PARAM_HIGH_E;
        }
        else if (is_validIP(arg)) // je to ip-prefix
        {
            ip_prefix.push_back(argv[i]); // ulozenie ip-prefixov
        }
        else
        {
            cerr << "Zadali ste neznami/nespravny parameter " << arg << endl;
            cerr << "Spustenie programu: ./dhcp-stats [-help] [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]" << endl;
            return PARAM_E;
        }
    }

    //------------------------------------------------------------Odchytavanie DHCP paketov------------------------------------------------------------
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    // char filter_exp[] = "port 67 or vlan";
    char filter_exp[] = "port 67 or port 68";
    struct bpf_program fp; // pre ulozenie skompilovaneho filtru

    signal(SIGINT, Signal_handler);

    /*------------------------------------------------------------------------------------------INSPIROVANE - http://yuba.stanford.edu/~casado/pcap/section4.html ---------------------------------------------------------------------------*/
    if (file_or_interface == 0)
    {
        initscr(); // spusti ncursed mod
        print_ncurses();
        print_stats();
        refresh();

        const char *c_interface_name = interface_name.c_str();
        descr = pcap_open_live(c_interface_name, BUFSIZ, 0, 10, errbuf); // otvor zariadenie na odpocuvanie (eth0...)
        if (descr == NULL)
        {
            cerr << "Chyba: " << errbuf << endl;
            return PCAP_E;
        }
    }
    else
    {
        const char *c_filename = pcap_file.c_str();
        descr = pcap_open_offline(c_filename, errbuf); // otvor pcap subor na analyzu
        if (descr == NULL)
        {
            cerr << "Chyba: " << errbuf << endl;
            return PCAP_E;
        }
    }

    if (pcap_compile(descr, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) // skompiluj filter
    {
        cerr << "Chyba pri kompilacii filtra" << pcap_geterr(descr) << endl;
        return PCAP_E;
    }

    if (pcap_setfilter(descr, &fp) == -1) // nastav filter
    {
        cerr << "Chyba pri nastavovani filtra" << pcap_geterr(descr) << endl;
        return PCAP_E;
    }
    pcap_freecode(&fp);                                                   // uvolni pamat po nastavemi filtru
    pcap_loop(descr, -1, packetProcessing, (u_char *)&file_or_interface); // odchytavaj packety
    pcap_close(descr);
    /*------------------------------------------------------------------------------------------INSPIROVANE - http://yuba.stanford.edu/~casado/pcap/section4.html ---------------------------------------------------------------------------*/

    if (file_or_interface == 1)
    {
        cout << "IP-Prefix  Max-hosts Allocated addresses Utilization" << endl;
        for (const auto &pair : stats)
        {
            const std::string &subnet_prefix = pair.first;
            const subnet_stats &subnet_stats = pair.second;
            printf("%s ", subnet_prefix.c_str());
            printf("%ld ", subnet_stats.max_hosts);
            printf("%ld ", subnet_stats.allocated_addrs);
            printf("%.2f%% \n", subnet_stats.utilization);
            if (subnet_stats.utilization > 50)
            {
                cout << "prefix " << subnet_prefix << " exceeded 50% of allocations" << endl;
            }
        }
    }

    return 0;
}