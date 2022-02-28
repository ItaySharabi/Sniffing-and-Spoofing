from scapy.all import *
# Task 1B: A sniffing program that sniffs packets 
# that are coming from or going to subnet: 10.11.12.0/24.
def got_packet(pkt):

	pkt.show()
print('Sniffing on subnet 10.11.12.0/24')
pkt = sniff(iface='enp0s3', filter='net 10.11.12.0/24', prn=got_packet)
