# Task 1.3 Traceroute: 
# In this task we've automated packet sending
# with increasing ttl, so we can count how many routers
# are there on our way to dest ip is Apple.com (17.253.144.10)
from scapy.all import *
import time

def traceroute(pkt):
	print('Tracing...')
	for i in range(13):
		pkt.ttl = i+1 # increase ttl each round.
		send(pkt, verbose=0)
		time.sleep(0.5) # wait for responses.
	print('Done')

a = IP(dst='Apple.com') # Some random out of network ip.
b = ICMP()	      # Default ICMP ping-req
p = a/b

traceroute(p)
