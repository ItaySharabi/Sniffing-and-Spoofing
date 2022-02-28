#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

#define ICMP_HDRLEN 8
#define IP4_HDRLEN 20

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}

int createSock();

// HERE NEED TO ADD THE PAYLOAD TO NEW PACKET.
void spoofPacket(struct iphdr *ip, struct icmphdr *icmp){

    int sockfd = createSock();

    struct ip iphdr; // IPv4 header
    struct icmp icmphdr; // ICMP-header
    char data[BUFSIZ] = "This is a ping\n"; //(struct iphdr *) ip + IP4_HDRLEN + ICMP_HDRLEN;

    int datalen = strlen(data) + 1;

    //==================
    // IP header
    //==================

    // IP protocol version (4 bits)
    iphdr.ip_v = 4;

    // IP header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / 4; 

    // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
    iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

    // ID sequence number (16 bits): not in use since we do not allow fragmentation
    iphdr.ip_id = 0;

    // TTL (8 bits): 128 - you can play with it: set to some reasonable number
    iphdr.ip_ttl = 100;

    // Upper protocol (8 bits): ICMP is protocol number 1
    iphdr.ip_p = IPPROTO_ICMP;

    // Switch src and dst.
    struct sockaddr_in src, dest;
    src.sin_addr.s_addr = ip->daddr;
    dest.sin_addr.s_addr = ip->saddr;


    // Source IP 
    if (inet_pton(AF_INET, inet_ntoa(src.sin_addr), &(iphdr.ip_src)) <= 0) 
    {
        printf ("inet_pton() failed for source-ip with error: %d", errno);
        return;
    }

    // Destination IP
    if (inet_pton (AF_INET, inet_ntoa(dest.sin_addr), &(iphdr.ip_dst)) <= 0)
    {
        printf ("inet_pton() failed for destination-ip with error: %d" , errno);
        return;
    }

    // IPv4 header checksum (16 bits): set to 0 prior to calculating in order not to include itself.
    iphdr.ip_sum = 0;
    iphdr.ip_sum = calculate_checksum((unsigned short *) &iphdr, IP4_HDRLEN);


    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHOREPLY;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // printf("id: %d\n seq: %d\n", htons(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));

    // // Identifier (16 bits): some number to trace the response.
    // // It will be copied to the response packet and used to map response to the request sent earlier.
    // // Thus, it serves as a Transaction-ID when we need to make "ping"
    // icmphdr.icmp_hun.ih_idseq.icd_id = ntohs(icmp->un.echo.id);  // ntohs
    
    icmphdr.icmp_id = icmp->un.echo.id;
    
    // // Sequence Number (16 bits): Should be matched with the packet we sniffed
    // icmphdr.icmp_hun.ih_idseq.icd_seq = ntohs(icmp->un.echo.sequence);
    icmphdr.icmp_seq = icmp->un.echo.sequence;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet
    char packet[IP_MAXPACKET];

    // First, IP header.
    memcpy (packet, &iphdr, IP4_HDRLEN);

    // Next, ICMP header
    memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy (packet + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet + IP4_HDRLEN), ICMP_HDRLEN + datalen);
    memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    // The port is irrelant for Networking and therefore was zeroed.
    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;
    printf("Source: %s\n", inet_ntoa(src.sin_addr));
    printf("Dest: %s\n", inet_ntoa(dest.sin_addr));


    int pkt_size = ETHER_HDR_LEN + IP4_HDRLEN + ICMP_HDRLEN;

    if (sendto (sockfd, packet, pkt_size, 0, (struct sockaddr *)&dest, sizeof (dest)) == -1)  
    {
        printf ("sendto() failed with error: %d", errno);
        return;
    }

    printf("Spoofed!\n");

    close(sockfd);

    return;
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    // Check Ethernet header for an IP packet:
    struct ether_header *eth = (struct ether_header *) packet;
    if (eth->ether_type != ntohs(ETHERTYPE_IP))
    {
        printf("Not an IP Packet, skipping...\n");
        return;
    }
    
    // printf("It's an IP Packet!\n");

    struct iphdr *ip_hdr = (struct iphdr *)(packet + ETHER_HDR_LEN);

    // Check IP Header for an ICMP header: 
    if (ip_hdr->protocol == IPPROTO_ICMP)
        {
            // printf("It's an ICMP Packet!\n");
            struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + (4 * ip_hdr->ihl));

            int t = (unsigned int)(icmp_hdr->type);
            int c = (unsigned int)(icmp_hdr->code);

            // ICMP header of type 0 is Echo (Reply), and type 8 is Echo.
            // We capture our sent ping to 8.8.8.8(Echo),
            // or Echo replies from outside.
            if (t == 8)
            {
                
                // Get source IP Address:
                struct sockaddr_in source, dest;
                memset(&source, 0, sizeof(source));
                source.sin_addr.s_addr = ip_hdr->saddr;

                // Get destination IP Address:
                memset(&dest, 0, sizeof(dest));
                dest.sin_addr.s_addr = ip_hdr->daddr;


                printf("IP Addresses:\n");
                printf("Source: %s\n", inet_ntoa(source.sin_addr));
                printf("Destination: %s\n", inet_ntoa(dest.sin_addr));

                printf("Now let's spoof a response to that packet:\n");
                
                spoofPacket(ip_hdr, icmp_hdr);
                printf("--------------------\n");

            }
        }

}

// This code was taken from our 4'th course assignment, and was modified by us.
// Additionally combined with our code and some packet layer handling code.
// Logically the code was designed by us.
int main() {

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_set_promisc(handle,1);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // int sockfd = createSock(); // returns the socket filedescriptor

    
    // Step 3: Capture packets
    printf("Sniffing ICMP packets...\n"); 
    pcap_loop(handle, 0, got_packet, NULL);
    pcap_close(handle); //Close the handle

    return 0;
}


int createSock(){
   
    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) 
    {
        printf ("socket() failed with error: %d", errno);
        printf ("To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    // This socket option IP_HDRINCL says that we are building IPv4 header by ourselves, and
    // the networking in kernel is in charge only for Ethernet header.

    const int flagOne = 1;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &flagOne, sizeof (flagOne)) == -1) 
    {
        printf ("setsockopt() failed with error: %d", errno);
        return -1;
    }

    return sock;
}