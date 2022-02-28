#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/socket.h>

/*This function will be invoked by pcap for each captured packet.We can process each packet inside the function.*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){


	/* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != 0x0800) {
        return;
    }

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;

    /* Find start of IP header */
	struct iphdr *ip = (void *)packet + ethernet_header_length;


	struct in_addr *src, *dst;
	src = (struct in_addr *)(&ip->saddr);
	dst = (struct in_addr *)(&ip->daddr);

	printf("Source IP: %s\n", inet_ntoa(*src));
	printf("Destination IP: %s\n\n", inet_ntoa(*dst));
}
// This code was taken from SEED LABS.
// Additionally combined with our code and some packet info printing code.
// Logically the code was designed by us.
int main(){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;	
	char filter_exp[] = ""; // No filter
	bpf_u_int32 net;
// Step 1: Open live pcap session on NIC with name enp0s3
	printf("Sniffing Packets...\n");
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
// Step 2: Compile filter_exp into BPF psuedo-code

	pcap_set_promisc(handle, 0); // Turning promiscuous mode does not do anything.
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

// Step 3: Capture packets

	pcap_loop(handle, -1, got_packet, NULL);

//Close the handle
	pcap_close(handle);
return 0;
}
