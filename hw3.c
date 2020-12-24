#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <pcap.h>

#define OFFMASK 0x1fff
#define MAX_IP 128
#define FILE_LEN 20
#define MAC_ADDLEN 18
typedef unsigned char u_char;
typedef unsigned int u_int;

// record number of connection
typedef struct{ 
    int num;
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
}Counter;
Counter counter[MAX_IP];
int pair_cnt = 0;

// transform mac address
char *mac_ntoa(u_char *d) {
    static char str[MAC_ADDLEN];

    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return str;
}

void dump_tcp(u_int32_t length, const u_char *content) {
	struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    // determine endianness
	u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
	printf(">>Protocol: TCP\n");
    printf("| Source Port:       %7u| Destination Port:  %7u|\n", source_port, destination_port);
    printf("\n");
}

void dump_udp(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    // determine endianness
    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);
    u_int16_t len = ntohs(udp->uh_ulen);
    u_int16_t checksum = ntohs(udp->uh_sum);

    printf(">>Protocol: UDP\n");
    printf("| Source Port:       %7u| Destination Port:  %7u|\n", source_port, destination_port);
    printf("| Length:            %7u| Checksum:          %7u|\n", len, checksum);
    printf("\n");
    
}

// record source IP and destination IP
void IP_count(char *srcIP, char *dstIP){
    int i;
    for(i=0; i < MAX_IP; i++){
        if(strcmp(srcIP, counter[i].srcIP) == 0 && strcmp(dstIP, counter[i].dstIP) == 0){
            counter[i].num++;
            break;
        }
        else if(strlen(counter[i].srcIP) == 0){
            strcpy(counter[i].srcIP, srcIP);
            strcpy(counter[i].dstIP, dstIP);
            counter[i].num++;
            pair_cnt++;
            break;
        }
    }
}

void record_counter(){
    int i, cnt=0;

    printf("---------------IP count---------------\n");
    for(i = 0; i < pair_cnt; i++){
        printf("%s -> %s : %d\n",counter[i].srcIP, counter[i].dstIP, counter[i].num);
        cnt += counter[i].num;
    }
    printf("The total of record: %d\n", cnt);   
}

void usage(){
    printf("argument wrong\n");
    printf("usage:./read_cap {pcap file}\n");
    exit(0);
}


int main(int argc, char **argv){
    char *file_name = NULL;
    if(argc != 2){
        usage();
    }else if(argc == 2){
        file_name = argv[1];
    }

    // file open 
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handler = pcap_open_offline(file_name, errbuff);
    char *dev;

    // header structure
    struct pcap_pkthdr *header;
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;

    char src_ip[INET_ADDRSTRLEN];   // source IP
    char dst_ip[INET_ADDRSTRLEN];   // destination IP

    for(int i = 0; i < MAX_IP; i++){
        counter[i].num = 0;
        memset(counter[i].srcIP, '\0', INET_ADDRSTRLEN);
        memset(counter[i].dstIP, '\0', INET_ADDRSTRLEN);
    }

    const u_char *packet;
    int packet_cnt = 0;
    u_int size_ip;
    u_int size_tcp;
    time_t tmp;
    struct tm ts;
	char dateBuf[80];
	int ret;

    u_char protocol;

    while((ret = pcap_next_ex(handler, &header, &packet)) >= 0){
        if(ret == 0)continue;

        char dst_mac[MAC_ADDLEN] = {};
    	char src_mac[MAC_ADDLEN] = {};
		u_int16_t type;
        printf("Packet #%d:\n",++packet_cnt);

        // time stamp
        tmp = header->ts.tv_sec;
        ts = *localtime(&tmp);
        strftime(dateBuf, sizeof(dateBuf), "%m/%d/%Y %a %H:%M:%S", &ts);

        printf("Time %s\n", dateBuf);
		printf("Length: %d bytes\t", header->len);
    	printf("Capture length: %d bytes\n", header->caplen);

        eth_header = (struct ether_header *) packet;

        //  mac address
		strncpy(dst_mac, mac_ntoa(eth_header->ether_dhost), sizeof(dst_mac));
		strncpy(src_mac, mac_ntoa(eth_header->ether_shost), sizeof(src_mac));
		type = ntohs(eth_header->ether_type);
		printf("| Destination MAC Address:       %18s     |\n", dst_mac);
		printf("| Source MAC Address:            %18s     |\n", src_mac);
        printf("\n");

        // Protocol is IP
		if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
			ip_header = (struct ip*)(packet + sizeof(struct ether_header));
            // get protocol, such as TCP,UDP,...
            protocol = ip_header->ip_p;

			inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        	printf(">Protocol: IP\n");
			printf("| Source IP Address:                   %17s|\n", src_ip);
			printf("| Destination IP Address:              %17s|\n", dst_ip);
			// record source IP and destination IP
            IP_count(src_ip, dst_ip);

			// handle UDP and TCP
			switch (protocol) {
				case IPPROTO_UDP:
					dump_udp(header->caplen, packet);
					break;

				case IPPROTO_TCP:
					dump_tcp(header->caplen, packet);
					break;
			}
		}
		else if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
			printf(">>ARP\n");
		}
		else if(ntohs(eth_header->ether_type) == ETHERTYPE_REVARP){
			printf(">>Reverse ARP\n");
		}
		else{
			printf(">>not support\n");
		}
        printf("\n");
    }

    record_counter();

    return 0;
}