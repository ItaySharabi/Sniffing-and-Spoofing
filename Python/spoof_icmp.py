from scapy.all import *
# Task 1.2: Spoofing an icmp packet:
# 10.0.2.5 should get a ping req from 10.0.2.1 and reply to him, 
# while 10.0.2.1 never sent a ping to 10.0.2.5

a = IP(src='10.0.2.1', dst='10.0.2.5')
b = ICMP() # type=8 by default (ping-request)
send(a/b, verbose=0) # Spoof!
print('Spoofed an icmp ping-req from 10.0.2.1 to 10.0.2.5!')
