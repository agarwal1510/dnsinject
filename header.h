#ifndef HEADER_H
#define HEADER_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include<pcap.h>
#include<netinet/ether.h>
#include<netinet/if_ether.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<stdint.h>
#include<string.h>
#include<arpa/inet.h>
#include <libnet.h>
#include <netinet/udp.h>
#include <resolv.h>
#include <arpa/nameser.h>

#define ETHERTYPE_IP 0x0800
#define SIZE_ETHERNET 14
#define IP_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define DNS_HEADER_SIZE 12



struct dnshdr   {
        unsigned    id:      16;
        unsigned    rd:       1;
        unsigned    tc:       1;
        unsigned    aa:       1;
        unsigned    opcode:   4;
        unsigned    qr:       1;
        unsigned    rcode:    4;
        unsigned    cd:       1;
        unsigned    ad:       1;
        unsigned    unused:   1;
        unsigned    ra:       1;
        unsigned    qdcount: 16;
        unsigned    ancount: 16;
        unsigned    nscount: 16;
        unsigned    arcount: 16;
};


#endif

