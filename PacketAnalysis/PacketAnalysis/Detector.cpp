#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#define ETHER_ADDR_LEN 6

#define HAVE_REMOTE
#include<stdlib.h>
#include<stdio.h>
#include<string.h>

#include<regex>
#include<iostream>
#include<string>

using namespace std;

#include<pcap.h>

typedef struct mac_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;


typedef struct ether_header {
	u_char ether_dhost[ETHER_ADDR_LEN]; //d_mac_addr
	u_char ether_shost[ETHER_ADDR_LEN]; //s_mac_addr
	u_short ether_type; //패킷 유형(이더넷 헤더 다음에 붙을 헤더의 심볼정보 저장)
}eth;

using namespace std;

typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;


typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

typedef struct tcp_header {
	WORD sport;					// source port
	WORD dport;					// destination port
	DWORD seqno;				// sequenz number
	DWORD ackno;				// acknowledge number
	BYTE hlen;					// Header length
	BYTE flag;					// flags
	WORD window;				// window
	WORD chksum;				// checksum
	WORD urgptr;				// urgent pointer
}tcp_header;

void ifprint(int index, pcap_if_t *d);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
u_long retrieveIP(pcap_if_t* d);
int compareIP(struct ip_address a, struct ip_address b);
string ip24tos(ip_address in);

int main() {

	printf("패킷 캡쳐 프로그램을 시작합니다.\n");
	printf("☆☆☆☆☆☆☆탐지는 되나, 속도가 많이 느리므로☆☆☆☆☆☆☆\n");
	printf("☆☆test페이지 접속후에 탐지 될 때까지 좀 기다려 주세요..☆☆\n");
	printf("☆☆캐시를 모두 지우고, 상황에 따라 10초정도 기다릴때도..☆☆\n\n");
	printf("☆☆과제를 하나씩 남기고 주석처리하면서, test하는게 눈건강에 이롭..☆☆\n\n");
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d != NULL; d = d->next)
	{
		ifprint(++i, d);
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the NIC # to capture packets (1-%d): ", i);
	int inum;
	scanf_s("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\nNIC number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	pcap_t *adhandle;
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture (in bytes)
						  // 65536 guarantees that the entire packet will be captured over all layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout (1 second)
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter - not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}


	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	u_int netmask;
	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface comes without any address, we suppose it to be in a class-C network */
		netmask = 0xffffff;

	char packet_filter[] = "ip and tcp";
	struct bpf_program fcode;
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\n다음 NIC에서 캡쳐를 시작합니다:\n");
	if (d->description)
		printf("%s\n", d->description);
	else
		printf("the selected NIC\n");

	/* 선택한 NIC의 ip주소를 읽어와 저장 */
	/* LSB - MSB 차례로 저장되어있음에 주의 (즉, 192.168.219.5는 00000101 (5), 11011011 (219), 10101000 (168), 11000000 (192) 차례로 저장되어 있음) */
	u_long NIC_IP_in_long = retrieveIP(d);
	//printf("NIC_IP: <%lu>\n", NIC_IP_in_long);
	/* packet의 ip header에서 ip 주소가 저장되는 구조체와 동일한 구조체에 이를 넣음 (후에 비교하기 쉽기 위해) */
	struct ip_address nic_ip;
	nic_ip.byte1 = NIC_IP_in_long & 0xFF;
	NIC_IP_in_long >>= 8;
	nic_ip.byte2 = NIC_IP_in_long & 0xFF;
	NIC_IP_in_long >>= 8;
	nic_ip.byte3 = NIC_IP_in_long & 0xFF;
	NIC_IP_in_long >>= 8;
	nic_ip.byte4 = NIC_IP_in_long & 0xFF;
	printf("%d.%d.%d.%d\n",
		nic_ip.byte1,
		nic_ip.byte2,
		nic_ip.byte3,
		nic_ip.byte4
	);
	printf("\n=================================\n");

	pcap_freealldevs(alldevs);


	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		struct tm ltime;
		char timestr[16];
		time_t local_tv_sec;
		ip_header *ih;
		u_int ip_len;
		tcp_header *th;
		u_short sport, dport;
		u_int th_len;			// tcp header 의 길이
								//u_int p_len;//sunghee
	

		char* payload;

		if (res == 0)
			/* Timeout elapsed */
			continue;

		local_tv_sec = header->ts.tv_sec;
		localtime_s(&ltime, &local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	
		ih = (ip_header *)(pkt_data + 14); //length of ethernet header

										  
		ip_len = (ih->ver_ihl & 0xf) * 4;			// ip header 의 길이가 이 부분에 4를 곱한 Bytes수임
		th = (tcp_header *)((u_char*)ih + ip_len);	// ip header 를 지난 부분이 TCP header 의 시작 부분

													/* convert from network byte order to host byte order (네트워크와 호스트OS에서 사용하는 byte 순서가 다를 경우 변환해 줌)*/
		sport = ntohs(th->sport);
		dport = ntohs(th->dport);

		/* payload에 대한 pointer 읽어오기 */

		th_len = ((th->hlen & 0xf0) >> 4) * 4;
		payload = (char*)th + th_len;


		/*
		과제1&2 : 출발지/도착지 mac# 출력(탐지조건 아니라 무조건 뜨게!)
		*/

		// 이더넷 헤더
		mac_address *srcmac;
		mac_address *destmac;
		destmac = (mac_address *)pkt_data;
		srcmac = (mac_address *)(pkt_data + 6);

		// smac, dmac 출력
		printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n\n",
			srcmac->byte1,
			srcmac->byte2,
			srcmac->byte3,
			srcmac->byte4,
			srcmac->byte5,
			srcmac->byte6,

			destmac->byte1,
			destmac->byte2,
			destmac->byte3,
			destmac->byte4,
			destmac->byte5,
			destmac->byte6);

		//과제1&2끝

		 /*
		 과제3 : 출발지port#가 80인 경우에 요약정보 출력
		 */
		if (sport == 80) {  //sport==80이면 출력(tcp_header, udp_header 구조체 참고)
							// 패킷의 도착시간, 길이 (in bytes) 출력
			printf("%s.%.6d (%dB) ", timestr, header->ts.tv_usec, header->len);

			// source ip, source port#, destination ip, destination port# 출력 
			printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
				ih->saddr.byte1,
				ih->saddr.byte2,
				ih->saddr.byte3,
				ih->saddr.byte4,
				sport,
				ih->daddr.byte1,
				ih->daddr.byte2,
				ih->daddr.byte3,
				ih->daddr.byte4,
				dport
			);

			if (compareIP(ih->saddr, nic_ip) == 0) { printf("  >>> outbound >>>\n"); }
			else { printf("  <<< inbound <<<\n"); }

			printf("sPort=80 detected\n");
		}//과제3끝


		 /*
		 과제4 : 목적지port#가 80인 경우에 요약정보 출력
		 */
		if (dport == 80) {  //dport==80이면 출력(tcp_header, udp_header 구조체 참고)
							// 패킷의 도착시간, 길이 (in bytes) 출력
			printf("%s.%.6d (%dB) ", timestr, header->ts.tv_usec, header->len);

			// source ip, source port#, destination ip, destination port# 출력 
			printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
				ih->saddr.byte1,
				ih->saddr.byte2,
				ih->saddr.byte3,
				ih->saddr.byte4,
				sport,
				ih->daddr.byte1,
				ih->daddr.byte2,
				ih->daddr.byte3,
				ih->daddr.byte4,
				dport
			);

			if (compareIP(ih->saddr, nic_ip) == 0) { printf("  >>> outbound >>>\n"); }
			else { printf("  <<< inbound <<<\n"); }

			printf("dPort=80 detected\n");
		}//과제4끝

		 /*
		 과제5 : 출발지 IP#가 192.168.1.75(내가 사용중인 카페 IP)인 경우에 요약정보 출력
		 */
		if (ih->saddr.byte1 == 192 && ih->saddr.byte2 == 168 && ih->saddr.byte3 == 1 && ih->saddr.byte4 == 75) {  //목적지IP가 203.246.40.6인경우출력
																												  // 패킷의 도착시간, 길이 (in bytes) 출력												//ip_header 구조체 참고
			printf("%s.%.6d (%dB) ", timestr, header->ts.tv_usec, header->len);

			// source ip, source port#, destination ip, destination port# 출력 
			printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
				ih->saddr.byte1,
				ih->saddr.byte2,
				ih->saddr.byte3,
				ih->saddr.byte4,
				sport,
				ih->daddr.byte1,
				ih->daddr.byte2,
				ih->daddr.byte3,
				ih->daddr.byte4,
				dport
			);

			if (compareIP(ih->saddr, nic_ip) == 0) { printf("  >>> outbound >>>\n"); }
			else { printf("  <<< inbound <<<\n"); }

			printf("cafe IP# detected\n");
		}//과제5끝


		 /*
		 과제6 : 목적지 IP#가 203.246.40.6(접속지 서울여대)인 경우에 요약정보 출력
		 */
		if (ih->daddr.byte1 == 203 && ih->daddr.byte2 == 246 && ih->daddr.byte3 == 40 && ih->daddr.byte4 == 6) {  //목적지IP가 203.246.40.6인경우출력
																												  // 패킷의 도착시간, 길이 (in bytes) 출력												//ip_header 구조체 참고
			printf("%s.%.6d (%dB) ", timestr, header->ts.tv_usec, header->len);

			// source ip, source port#, destination ip, destination port# 출력 
			printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
				ih->saddr.byte1,
				ih->saddr.byte2,
				ih->saddr.byte3,
				ih->saddr.byte4,
				sport,
				ih->daddr.byte1,
				ih->daddr.byte2,
				ih->daddr.byte3,
				ih->daddr.byte4,
				dport
			);

			if (compareIP(ih->saddr, nic_ip) == 0) { printf("  >>> outbound >>>\n"); }
			else { printf("  <<< inbound <<<\n"); }

			printf("SWU detected\n");
		}//과제6끝


		 /*
		 과제7 : DATA아무거나 탐지하기 : payload에 200 OK 가 실린경우 요약정보 출력
		 */

		if (strncmp(payload, "HTTP", 4) == 0) {					 // payload의 첫 4 bytes가 "HTTP"인 경우(200 ok는 http여야함)
			char *pch = strstr(payload, "200 OK");
			if (pch != NULL) {									// 위 string을 payload에 포함하는 경우 
																// 패킷의 도착시간, 길이 (in bytes) 출력
				printf("%s.%.6d (%dB) ", timestr, header->ts.tv_usec, header->len);

				// source ip, source port#, destination ip, destination port# 출력 
				printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
					ih->saddr.byte1,
					ih->saddr.byte2,
					ih->saddr.byte3,
					ih->saddr.byte4,
					sport,
					ih->daddr.byte1,
					ih->daddr.byte2,
					ih->daddr.byte3,
					ih->daddr.byte4,
					dport
				);

				if (compareIP(ih->saddr, nic_ip) == 0) { printf("  >>> outbound >>>\n"); }
				else { printf("  <<< inbound <<<\n"); }

				printf("200 OK detected\n");
			}
		}//과제7끝


	}	// end of while loop

	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	return 0;
}

int compareIP(struct ip_address a, struct ip_address b) {
	int rt_val = 1;

	if ((a.byte1 == b.byte1) &&
		(a.byte2 == b.byte2) &&
		(a.byte3 == b.byte3) &&
		(a.byte4 == b.byte4))
	{
		rt_val = 0;		//equal ip addresses
	}

	return rt_val;
}

u_long retrieveIP(pcap_if_t* d) {
	pcap_addr_t *a;
	u_long ipv4_addr;

	for (a = d->addresses; a; a = a->next) {
		switch (a->addr->sa_family)
		{
		case AF_INET:	// IPv4 address			
			if (a->addr)
				ipv4_addr = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
			break;
		}
	}

	return ipv4_addr;
}

void ifprint(int index, pcap_if_t *d)
{
	pcap_addr_t *a;
	char ip6str[128];

	printf("%d. ", index);
	if (d->description)
		printf(" (%s)\n", d->description);
	else
		printf(" (No description available)\n");

	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	/* NIC에 할당된 IP addresses 출력 */
	for (a = d->addresses; a; a = a->next) {
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tIPv4 address: ");
			if (a->addr)
				printf("%s ", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("%s ", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			printf("\n");
			break;

		case AF_INET6:
			printf("\tIPv6 address: ");
			if (a->addr)
				printf("%s", ip6tos(a->addr, ip6str, sizeof(ip6str)));
			printf("\n");
			break;

		default:
			printf("\tUnknown address type\n");
			break;
		}
	}
	printf("\n");
}



/* Convert a numeric IPv4 address to a string (ifprint 함수 내에서 사용됨) */
#define IPTOSBUFFERS    12		// # of IP string buffers
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);	// move to the next string buffer, wrapping if necessary
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

/* numeric IP의 /24 prefix 부분만 string으로 변환 */
string ip24tos(ip_address in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;

	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.*", in.byte1, in.byte2, in.byte3);
	return string(output[which]);
}

/* Convert a IPv6 address to a string */
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

	sockaddrlen = sizeof(struct sockaddr_in6);

	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}