from scapy.all import *
# Task 1A: A simple sniffing program that was given to us.
def got_packet(pkt):

	pkt.show()
print('Sniffing...')
pkt = sniff(iface='enp0s3', filter='icmp', prn=got_packet)
