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

#ifndef ARP_ATTACKER_H
#define ARP_ATTACKER_H

#define	ETH_LEN	6
#define	MAC_LEN	6
#define	IP_LEN	16

extern int  ok_flag;
extern char eth[ETH_LEN];
extern char	local_ip[IP_LEN];
extern char	local_mac[MAC_LEN];
extern char	attack_ip[IP_LEN];
extern char	attack_mac[MAC_LEN];
extern char	fake_ip[IP_LEN];
extern char	fake_mac[MAC_LEN];

/* *
 * read configuration
 * */
void read_config();

/* *
 * get local IP & MAC
 * */
void get_local_ip_mac();

/* *
 * analyse ARP reply packet to get dest MAC
 * */
void arp_parse();

/* *
 * send ARP request packet to dst host
 * */
void build_arp_request();

/* *
 * send ARP deceive packet
 * */
void build_arp_reply();

#endif
