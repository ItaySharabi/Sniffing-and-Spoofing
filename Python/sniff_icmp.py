from scapy.all import *
# Task 1B: An ICMP sniffing program.
def got_packet(pkt):

	pkt.show()
print('Sniffing ICMP...')
pkt = sniff(iface='enp0s3', filter='icmp', prn=got_packet)
