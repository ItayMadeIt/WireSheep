#include <pcap.h>
#include <Winsock2.h>
#include <Winsock.h>
#include <tchar.h>
#include <iostream>
BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}


/* 4 bytes IP address */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
    u_char  ver_ihl; // Version (4 bits) + IP header length (4 bits)
    u_char  tos;     // Type of service 
    u_short tlen;    // Total length 
    u_short identification; // Identification
    u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;      // Time to live
    u_char  proto;    // Protocol
    u_short crc;      // Header checksum
    ip_address  saddr; // Source address
    ip_address  daddr; // Destination address
    u_int  op_pad;     // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
    u_short sport; // Source port
    u_short dport; // Destination port
    u_short len;   // Datagram length
    u_short crc;   // Checksum
}udp_header;

/* prototype of the packet handler */
void packet_handler(u_char* param,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data);


int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[] = "ip and udp";
    struct bpf_program fcode;

    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }

    /* Retrieve the device list */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
        NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf_s("%d", &inum);

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* Open the adapter */
    if ((adhandle = pcap_open(d->name, // name of the device
        65536, // portion of the packet to capture. 
        // 65536 grants that the whole packet
        // will be captured on all the MACs.
        PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
        1000, // read timeout
        NULL, // remote authentication
        errbuf // error buffer
    )) == NULL)
    {
        fprintf(stderr,
            "\nUnable to open the adapter. %s is not supported by Npcap\n",
            d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if (d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses
         * we suppose to be in a C class network */
        netmask = 0xffffff;


    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data)
{
    struct tm ltime;
    char timestr[16];
    ip_header* ih;
    udp_header* uh;
    u_int ip_len;
    u_short sport, dport;
    time_t local_tv_sec;

    /*
     * Unused variable
     */
    (VOID)(param);

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    
    std::cout << local_tv_sec << " : " << header->ts.tv_usec << std::endl;

    /* retireve the position of the ip header */
    ih = (ip_header*)(pkt_data +
        14); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header*)((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs(uh->sport);
    dport = ntohs(uh->dport);

    /* print ip addresses and udp ports */
    printf("%d.%d.%d.%d : %d -> %d.%d.%d.%d : %d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,
        sport,
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4,
        dport);
}