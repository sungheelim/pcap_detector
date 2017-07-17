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
	u_short ether_type; //��Ŷ ����(�̴��� ��� ������ ���� ����� �ɺ����� ����)
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

	printf("��Ŷ ĸ�� ���α׷��� �����մϴ�.\n");
	printf("�١١١١١١�Ž���� �ǳ�, �ӵ��� ���� �����ǷΡ١١١١١١�\n");
	printf("�١�test������ �����Ŀ� Ž�� �� ������ �� ��ٷ� �ּ���..�١�\n");
	printf("�١�ĳ�ø� ��� �����, ��Ȳ�� ���� 10������ ��ٸ�����..�١�\n\n");
	printf("�١ٰ����� �ϳ��� ����� �ּ�ó���ϸ鼭, test�ϴ°� ���ǰ��� �̷�..�١�\n\n");
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

	printf("\n���� NIC���� ĸ�ĸ� �����մϴ�:\n");
	if (d->description)
		printf("%s\n", d->description);
	else
		printf("the selected NIC\n");

	/* ������ NIC�� ip�ּҸ� �о�� ���� */
	/* LSB - MSB ���ʷ� ����Ǿ������� ���� (��, 192.168.219.5�� 00000101 (5), 11011011 (219), 10101000 (168), 11000000 (192) ���ʷ� ����Ǿ� ����) */
	u_long NIC_IP_in_long = retrieveIP(d);
	//printf("NIC_IP: <%lu>\n", NIC_IP_in_long);
	/* packet�� ip header���� ip �ּҰ� ����Ǵ� ����ü�� ������ ����ü�� �̸� ���� (�Ŀ� ���ϱ� ���� ����) */
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
		u_int th_len;			// tcp header �� ����
								//u_int p_len;//sunghee
	

		char* payload;

		if (res == 0)
			/* Timeout elapsed */
			continue;

		local_tv_sec = header->ts.tv_sec;
		localtime_s(&ltime, &local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	
		ih = (ip_header *)(pkt_data + 14); //length of ethernet header

										  
		ip_len = (ih->ver_ihl & 0xf) * 4;			// ip header �� ���̰� �� �κп� 4�� ���� Bytes����
		th = (tcp_header *)((u_char*)ih + ip_len);	// ip header �� ���� �κ��� TCP header �� ���� �κ�

													/* convert from network byte order to host byte order (��Ʈ��ũ�� ȣ��ƮOS���� ����ϴ� byte ������ �ٸ� ��� ��ȯ�� ��)*/
		sport = ntohs(th->sport);
		dport = ntohs(th->dport);

		/* payload�� ���� pointer �о���� */

		th_len = ((th->hlen & 0xf0) >> 4) * 4;
		payload = (char*)th + th_len;


		/*
		����1&2 : �����/������ mac# ���(Ž������ �ƴ϶� ������ �߰�!)
		*/

		// �̴��� ���
		mac_address *srcmac;
		mac_address *destmac;
		destmac = (mac_address *)pkt_data;
		srcmac = (mac_address *)(pkt_data + 6);

		// smac, dmac ���
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

		//����1&2��

		 /*
		 ����3 : �����port#�� 80�� ��쿡 ������� ���
		 */
		if (sport == 80) {  //sport==80�̸� ���(tcp_header, udp_header ����ü ����)
							// ��Ŷ�� �����ð�, ���� (in bytes) ���
			printf("%s.%.6d (%dB) ", timestr, header->ts.tv_usec, header->len);

			// source ip, source port#, destination ip, destination port# ��� 
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
		}//����3��


		 /*
		 ����4 : ������port#�� 80�� ��쿡 ������� ���
		 */
		if (dport == 80) {  //dport==80�̸� ���(tcp_header, udp_header ����ü ����)
							// ��Ŷ�� �����ð�, ���� (in bytes) ���
			printf("%s.%.6d (%dB) ", timestr, header->ts.tv_usec, header->len);

			// source ip, source port#, destination ip, destination port# ��� 
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
		}//����4��

		 /*
		 ����5 : ����� IP#�� 192.168.1.75(���� ������� ī�� IP)�� ��쿡 ������� ���
		 */
		if (ih->saddr.byte1 == 192 && ih->saddr.byte2 == 168 && ih->saddr.byte3 == 1 && ih->saddr.byte4 == 75) {  //������IP�� 203.246.40.6�ΰ�����
																												  // ��Ŷ�� �����ð�, ���� (in bytes) ���												//ip_header ����ü ����
			printf("%s.%.6d (%dB) ", timestr, header->ts.tv_usec, header->len);

			// source ip, source port#, destination ip, destination port# ��� 
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
		}//����5��


		 /*
		 ����6 : ������ IP#�� 203.246.40.6(������ ���￩��)�� ��쿡 ������� ���
		 */
		if (ih->daddr.byte1 == 203 && ih->daddr.byte2 == 246 && ih->daddr.byte3 == 40 && ih->daddr.byte4 == 6) {  //������IP�� 203.246.40.6�ΰ�����
																												  // ��Ŷ�� �����ð�, ���� (in bytes) ���												//ip_header ����ü ����
			printf("%s.%.6d (%dB) ", timestr, header->ts.tv_usec, header->len);

			// source ip, source port#, destination ip, destination port# ��� 
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
		}//����6��


		 /*
		 ����7 : DATA�ƹ��ų� Ž���ϱ� : payload�� 200 OK �� �Ǹ���� ������� ���
		 */

		if (strncmp(payload, "HTTP", 4) == 0) {					 // payload�� ù 4 bytes�� "HTTP"�� ���(200 ok�� http������)
			char *pch = strstr(payload, "200 OK");
			if (pch != NULL) {									// �� string�� payload�� �����ϴ� ��� 
																// ��Ŷ�� �����ð�, ���� (in bytes) ���
				printf("%s.%.6d (%dB) ", timestr, header->ts.tv_usec, header->len);

				// source ip, source port#, destination ip, destination port# ��� 
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
		}//����7��


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

	/* NIC�� �Ҵ�� IP addresses ��� */
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



/* Convert a numeric IPv4 address to a string (ifprint �Լ� ������ ����) */
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

/* numeric IP�� /24 prefix �κи� string���� ��ȯ */
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