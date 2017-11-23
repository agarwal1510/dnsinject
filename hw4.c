#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include<pcap.h>
#include<netinet/ether.h>
#include<netinet/if_ether.h>
#include<netinet/ether.h>
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

char ip[100][16];
char hostname[100][128];



void readHostnameFile(char *filename) {
	int i = 0;
	char line[256];
	char ret[256];
	FILE *fd = fopen(filename, "r");
	if (fd == NULL) {
		fprintf(stderr, "Hostname file cannot be opened");
	} else {
		while (fgets(line, sizeof(line), fd) != NULL && strlen(line) > 1) {
			char *token = strtok(line, " ");
			while (token) {
				strcpy (ip[i], token);
				token = strtok(NULL, " ");
				strcpy(hostname[i],token);
				token = strtok(NULL, " ");
				fprintf(stderr, "%s %s", ip[i], hostname[i]);
				i++;
			}
		}
	}
	fclose(fd);
}

void handler(u_char *usrarg, const struct pcap_pkthdr* pkthdr, const u_char *packet) {
	const struct ethhdr *eptr = (struct ethhdr*)(packet);
	if (ntohs(eptr->h_proto) != ETHERTYPE_IP) {
		return;
	}
	const struct ip *ip = (struct ip*) (packet + SIZE_ETHERNET);
	u_int size_ip = (ip->ip_hl)*4;
        if (size_ip < 20) {
                return;
	}
	if (ip->ip_p != IPPROTO_UDP) {
		return;
	}

	struct udphdr *udp;
	udp = (struct udphdr *) (packet + SIZE_ETHERNET + size_ip);
	if (ntohs(udp->dest) != 53) {
		return;
	}

	
	
	struct dnshdr *dns;
	dns = (struct dnshdr *) (packet + SIZE_ETHERNET + size_ip + UDP_HEADER_SIZE);
	
//	if (dns->opcode != QUERY) {
//		return;
//	}
	
	char *dns_payload = (char *) (packet + SIZE_ETHERNET + size_ip + UDP_HEADER_SIZE + DNS_HEADER_SIZE);
	
//	fprintf(stderr, "%s\n", dns_payload);
	char hostname[128];
	if (dn_expand((u_char *)dns, (u_char *)(packet + pkthdr->caplen), dns_payload, hostname, sizeof(hostname)) < 0) {
		return;
	}
	fprintf(stderr, "Hostname: %s\n", hostname);
	int type = (int)*(dns_payload + strlen(dns_payload) + 2);
	fprintf(stderr, "Type: %d", (int)*(dns_payload + strlen(dns_payload) + 2));
	if (type != T_A) {
		return;
	}

}

int main(int argc, char **argv) {

	int param = 1;
	char *interface = NULL, expr[256] = "", *hostname = NULL;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;


	if (argc > 1) {
		for (int j =1; j < argc; j=j+2) {
			if (strcmp(argv[j], "-i") == 0){
				interface = argv[j+1];
				param += 2;
				printf("interface found %s\n", interface);
			} else if (strcmp(argv[j], "-h") == 0) {
				param += 2;
				hostname = argv[j+1];
				printf("filename: %s\n",hostname);
			} 
		} 
		if (param < argc) {
			while (argc != param) {
				strcat(expr, argv[param]);
				strcat(expr, " ");
				param += 1;
			}
			printf("Expression: %s\n",expr);
		}
	}
	readHostnameFile(hostname);
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find device: %s\n", errbuf);
		return -1;
	}
	//printf("Dev: %s", dev);
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get net mask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	//        //if (filename != NULL) {
	//                handle = pcap_open_offline(filename, errbuf);
	//        } else {
	if (interface != NULL)
		handle = pcap_open_live(interface, 65535, 1, 1000, errbuf);
	else
		handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
	//        }
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device: %s\n", errbuf);
		return -1;
	}
	//if (pcap_datalink(handle) != DLT_EN10MB) {
	//      fprintf(stdout, "Only ethernet supported\n");
	//      return -1;
	//}     
	if (expr != NULL && pcap_compile(handle, &fp, expr, 0, net) == -1){
		fprintf(stderr, "Filter complie error %s\n", pcap_geterr(handle));
		return -1;
	}
	if (expr != NULL && pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Set filter error %s\n", pcap_geterr(handle));
		return -1;
	}
	// pcap_loop(pcap_t*, cnt, handler,u_char *userarg)
	pcap_loop(handle, -1, handler, hostname);
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;


}
