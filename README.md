# a-LAN-arp-attacker
## Introduction

send fake arp packets to one of the PC or all of the PCs in your LAN to deceive it(them), so that the PC(s) can not find the real host.

## library required

libpcap

libnet

## How to use it:

make

./arp_attacker [dst ip]

without dst ip, the program will send out broadcast. whose dst MAC is FF:FF:FF:FF:FF:FF, and this will effect the whole LAN.
