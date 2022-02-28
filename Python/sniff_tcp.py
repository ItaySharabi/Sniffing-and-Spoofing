from scapy.all import *
# Task 1B: A TCP sniffing program,
# that filters packets coming from 'chosen_src(10.0.2.5)' to dest port 23.
def got_packet(pkt):

	pkt.show()

print('Sniffing tcp from 10.0.2.5 to port 23...')
pkt = sniff(iface='enp0s3', filter='tcp and src host 10.0.2.5 and dst port 23', prn=got_packet)
