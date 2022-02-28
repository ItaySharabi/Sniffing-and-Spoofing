from scapy.all import *

def show(pkt):
	pkt.show()

	a = ARP(op='is-at')
	send(a)

print('Sniffing ARP...')
sniff(filter='arp', prn=show)
