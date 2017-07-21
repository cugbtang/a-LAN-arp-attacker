# a-LAN-arp-attacker
1. Introduction

send fake arp packets to one of the PC or all of the PCs in your LAN to deceive it(them), so that the PC(s) can not find the real host.

2. library required

libpcap
libnet

3. How to use it:

make
./arp_attacker [dst ip]
without dst ip, the program will send out broadcast. whose dst MAC is FF:FF:FF:FF:FF:FF, and this will effect the whole LAN.
