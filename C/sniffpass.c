#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);


/* Ethernet header */
struct ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        #define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
        #define IP_V(ip)                (((ip)->ip_vhl) >> 4)
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        u_char  th_flags;
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};



void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){
    
	/* declare pointers to packet headers */
	const struct ethernet *ethernet;  /* The ethernet header [1] */
	const struct ip *ip;              /* The IP header */
	const struct tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	
	/* define ethernet header */
	ethernet = (struct ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		return;
	}

    tcp = (struct tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		return;
	}


/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		print_payload(payload, size_payload);
	}

		return;
}

void print_payload(const u_char *payload, int len){

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}
void print_hex_ascii_line(const u_char *payload, int len, int offset){

	int i;
	int gap;
	const u_char *ch;


	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

// This code was taken from the internet, and was modified by us.
// Additionally combined with our code with some relevant logical changes to print out the packet's payload.
int main(){

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp and src host 10.0.2.5";
    bpf_u_int32 net;

// Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
// Step 2: Compile filter_exp into BPF psuedo-code
	pcap_set_promisc(handle, 1);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
// Step 3: Capture packets
    printf("Sniffing TCP from 10.0.2.5\n");
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);


return 0;
}