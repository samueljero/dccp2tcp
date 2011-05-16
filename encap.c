/******************************************************************************
Author: Samuel Jero

Date: 5/2011

Description: Encapsulation Functions for DCCP conversion to TCP

******************************************************************************/
#include "dccp2tcp.h"
#include "encap.h"
#include "pcap/sll.h"

/*Encapsulation start point and link layer selector*/
int do_encap(int link, struct pcap_pkthdr *h, u_char **nptr, int *nlength, const u_char **optr, int *length)
{
	switch(link){
		case DLT_EN10MB:
				/*Ethernet*/
				if(!ethernet_encap(h, nptr, nlength, optr, length)){
						return 0;
				}
				break;
		case DLT_RAW:
				/*Raw. Just IP*/
				if(!ipv4_encap(h, nptr, nlength, optr, length)){
						return 0;
				}
				break;
		case DLT_LINUX_SLL:
				/*Linux Cooked Capture*/
				if(!linux_cooked_encap(h, nptr, nlength, optr, length)){
					return 0;
				}
				break;
		default:
				dbgprintf(0, "Unknown Link Layer\n");
				return 0;
	}

	/*Adjust libpcap header*/
	if(h->caplen >= h->len || h->caplen >= *nlength){
		h->caplen=*nlength;
	}
	h->len=*nlength;

return 1;
}

/*Standard Ethernet Encapsulation*/
int ethernet_encap(struct pcap_pkthdr *h, u_char **nptr, int *nlength, const u_char **optr, int *length)
{
		struct ether_header		*ethh;
		int						next_len;
		int						next_nlen;
		u_char					*next_nptr;
		const u_char			*next_optr;

		/*Safety checks*/
		if(!h || !nptr || !nlength || !optr || !length || !*nptr || !*optr){
			dbgprintf(0,"Error: Ethernet Encapsulation Function given bad data!\n");
			return 0;
		}
		if(*length < sizeof(struct ether_header) || *nlength < sizeof(struct ether_header)){
			dbgprintf(0, "Error: Ethernet Encapsulation Function given packet of wrong size!\n");
			return 0;
		}

		/*Copy Ethernet header over*/
		memcpy(*nptr, *optr, sizeof(struct ether_header));

		/*Cast Pointer*/
		ethh=(struct ether_header*)(*nptr);

		/*Adjust pointers and lengths*/
		next_optr= *optr+ sizeof(struct ether_header);
		next_nptr= *nptr+ sizeof(struct ether_header);
		next_len= *length- sizeof(struct ether_header);
		next_nlen= *nlength- sizeof(struct ether_header);

		/*Select Next Protocol*/
		switch(ntohs(ethh->ether_type)){
			case ETHERTYPE_IP:
					if(!ipv4_encap(h, &next_nptr, &next_nlen, &next_optr, &next_len)){
							return 0;
					}
					break;
			default:
					dbgprintf(1, "Unknown Next Protocol at Ethernet\n");
					return 0;
					break;
		}

		/*Adjust length*/
		*nlength=next_nlen + sizeof(struct ether_header);
return 1;
}

/*IPv4 Encapsulation*/
int ipv4_encap(struct pcap_pkthdr *h, u_char **nptr, int *nlength, const u_char **optr, int *length)
{
		struct iphdr 			*iph;
		int						next_len;
		int						next_nlen;
		u_char					*next_nptr;
		const u_char			*next_optr;

		/*Safety checks*/
		if(!h || !nptr || !nlength || !optr || !length || !*nptr || !*optr){
			dbgprintf(0,"Error: IPv4 Encapsulation Function given bad data!\n");
			return 0;
		}
		if(*length < sizeof(struct iphdr) || *nlength < sizeof(struct iphdr)){
			dbgprintf(0, "Error: IPv4 Encapsulation Function given packet of wrong size!\n");
			return 0;
		}

		/*Copy IPv4 header over*/
		memcpy(*nptr, *optr, sizeof(struct iphdr));

		/*Cast Pointer*/
		iph=(struct iphdr*)(*nptr);

		/*Adjust pointers and lengths*/
		next_optr= *optr +iph->ihl*4;
		next_nptr= *nptr +iph->ihl*4;
		next_len= *length -iph->ihl*4;
		next_nlen= *nlength-iph->ihl*4;

		/*Confirm that this is IPv4*/
		if(iph->version!=4){
			dbgprintf(1, "Note: Packet is not IPv4\n");
			return 0;
		}

		/*Select Next Protocol*/
		switch(iph->protocol){
			case 0x21:
					/*DCCP*/
					if(!convert_packet(h, &next_nptr, &next_nlen, &next_optr, &next_len)){
						return 0;
					}
					break;
			default:
					dbgprintf(1, "Unknown Next Protocol at IPv4\n");
					return 0;
					break;
		}

		/*set ip to indicate that TCP is next protocol*/
		iph->protocol=6;
		iph->check=htonl(0);

		/*Adjust length*/
		*nlength=next_nlen + iph->ihl*4;

		/*Determine if computed length is reasonable*/
		if(*nlength > 0xFFFF){
				dbgprintf(1, "Error: Given TCP header+data length is too large for an IPv4 packet!\n");
				return 0;
		}

		/*Adjust IPv4 header to account for packet's total length*/
		iph->tot_len=htons(*nlength);
return 1;
}

int linux_cooked_encap(struct pcap_pkthdr *h, u_char **nptr, int *nlength, const u_char **optr, int *length)
{
	struct sll_header	*slh;
	int					next_len;
	int					next_nlen;
	u_char				*next_nptr;
	const u_char		*next_optr;


	/*Safety checks*/
	if(!h || !nptr || !nlength || !optr || !length || !*nptr || !*optr){
		dbgprintf(0,"Error: SLL Encapsulation Function given bad data!\n");
		return 0;
	}
	if(*length < sizeof(struct sll_header) || *nlength < sizeof(struct sll_header)){
		dbgprintf(0, "Error: SLL Encapsulation Function given packet of wrong size!\n");
		return 0;
	}

	/*Copy SLL header over*/
	memcpy(*nptr, *optr, sizeof(struct sll_header));

	/*Cast Pointer*/
	slh=(struct sll_header*)(*nptr);

	/*Adjust pointers and lengths*/
	next_optr= *optr + sizeof(struct sll_header);
	next_nptr= *nptr + sizeof(struct sll_header);
	next_len= *length - sizeof(struct sll_header);
	next_nlen= *nlength- sizeof(struct sll_header);

	/*Confirm that this is SLL*/
	if(ntohs(slh->sll_pkttype) > 4){
		dbgprintf(1, "Note: Packet is not SLL (Linux Cooked Capture)\n");
		return 0;
	}

	/*Select Next Protocol*/
	switch(ntohs(slh->sll_protocol)){
		case ETHERTYPE_IP:
				if(!ipv4_encap(h, &next_nptr, &next_nlen, &next_optr, &next_len)){
						return 0;
				}
				break;
		default:
				dbgprintf(1, "Unknown Next Protocol at SLL\n");
				return 0;
				break;
	}

	/*Adjust length*/
	*nlength=next_nlen + sizeof(struct sll_header);
return 1;
}
