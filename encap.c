/******************************************************************************
Utility to convert a DCCP flow to a TCP flow for DCCP analysis via
		tcptrace. Encapsulation Functions for DCCP conversion to TCP.

Copyright (C) 2012  Samuel Jero <sj323707@ohio.edu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Author: Samuel Jero <sj323707@ohio.edu>
Date: 11/2012
******************************************************************************/
#include "dccp2tcp.h"
#include "encap.h"
#include "checksums.h"
#include <pcap/sll.h>
#include <netinet/ip6.h>

/*Encapsulation start point and link layer selector*/
int do_encap(int link, struct packet *new, const struct const_packet *old)
{
	switch(link){
		case DLT_EN10MB:
				/*Ethernet*/
				if(!ethernet_encap(new, old)){
						return 0;
				}
				break;
		case DLT_RAW:
				/*Raw. Just IP*/
				if(!ipv4_encap(new, old)){
						return 0;
				}
				break;
		case DLT_LINUX_SLL:
				/*Linux Cooked Capture*/
				if(!linux_cooked_encap(new, old)){
					return 0;
				}
				break;
		default:
				dbgprintf(0, "Unknown Link Layer\n");
				return 0;
	}

	/*Adjust libpcap header*/
	if(new->h->caplen >= new->h->len || new->h->caplen >= new->length){
		new->h->caplen=new->length;
	}
	new->h->len=new->length;

return 1;
}

/*Standard Ethernet Encapsulation*/
int ethernet_encap(struct packet *new, const struct const_packet *old)
{
		struct ether_header	*ethh;
		struct const_packet nold;
		struct packet 		nnew;

		/*Safety checks*/
		if(!new || !old || !new->data || !old->data || !new->h || !old->h){
			dbgprintf(0,"Error: Ethernet Encapsulation Function given bad data!\n");
			return 0;
		}
		if(old->length < sizeof(struct ether_header) || new->length < sizeof(struct ether_header)){
			dbgprintf(0, "Error: Ethernet Encapsulation Function given packet of wrong size!\n");
			return 0;
		}

		/*Copy Ethernet header over*/
		memcpy(new->data, old->data, sizeof(struct ether_header));

		/*Cast Pointer*/
		ethh=(struct ether_header*)(new->data);

		/*Adjust pointers and lengths*/
		nold.data= old->data+ sizeof(struct ether_header);
		nnew.data= new->data + sizeof(struct ether_header);
		nold.length= old->length - sizeof(struct ether_header);
		nnew.length= new->length - sizeof(struct ether_header);
		nnew.h=new->h;
		nold.h=old->h;

		/*Select Next Protocol*/
		switch(ntohs(ethh->ether_type)){
			case ETHERTYPE_IP:
					if(!ipv4_encap(&nnew, &nold)){
							return 0;
					}
					break;
			case ETHERTYPE_IPV6:
					if(!ipv6_encap(&nnew, &nold)){
							return 0;
					}
					break;
			default:
					dbgprintf(1, "Unknown Next Protocol at Ethernet\n");
					return 0;
					break;
		}

		/*Adjust length*/
		new->length=nnew.length + sizeof(struct ether_header);
return 1;
}

/*IPv6 Encapsulation*/
int ipv6_encap(struct packet *new, const struct const_packet *old)
{
		struct ip6_hdr 		*iph;
		struct packet		nnew;
		struct const_packet	nold;

		/*Safety checks*/
		if(!new || !old || !new->data || !old->data || !new->h || !old->h){
			dbgprintf(0,"Error: IPv6 Encapsulation Function given bad data!\n");
			return 0;
		}
		if(old->length < sizeof(struct ip6_hdr) || new->length < sizeof(struct ip6_hdr)){
			dbgprintf(0, "Error: IPv6 Encapsulation Function given packet of wrong size!\n");
			return 0;
		}

		/*Copy IPv6 header over*/
		memcpy(new->data, old->data, sizeof(struct ip6_hdr));

		/*Cast Pointer*/
		iph=(struct ip6_hdr*)(new->data);

		/*Adjust pointers and lengths*/
		nold.data= old->data + sizeof(struct ip6_hdr);
		nnew.data= new->data +sizeof(struct ip6_hdr);
		nold.length= old->length - sizeof(struct ip6_hdr);
		nnew.length= new->length - sizeof(struct ip6_hdr);
		nnew.h=new->h;
		nold.h=old->h;

		/*Confirm that this is IPv6*/
		if((ntohl(iph->ip6_ctlun.ip6_un1.ip6_un1_flow) & (0xF0000000)) == (60000000)){
			dbgprintf(1, "Note: Packet is not IPv6\n");
			return 0;
		}

		/*Select Next Protocol*/
		switch(iph->ip6_ctlun.ip6_un1.ip6_un1_nxt){
			case 33:
					/*DCCP*/
					nnew.id_len=16;
					nnew.src_id=malloc(nnew.id_len);
					nnew.dest_id=malloc(nnew.id_len);
					if(nnew.src_id==NULL||nnew.dest_id==NULL){
						dbgprintf(0,"Error: Couldn't allocate Memory\n");
						exit(1);
					}
					memcpy(nnew.src_id,&iph->ip6_src,nnew.id_len);
					memcpy(nnew.dest_id,&iph->ip6_dst,nnew.id_len);
					if(!convert_packet(&nnew, &nold)){
						return 0;
					}
					break;
			default:
					dbgprintf(1, "Unknown Next Protocol at IPv6\n");
					return 0;
					break;
		}

		/*set ip to indicate that TCP is next protocol*/
		iph->ip6_ctlun.ip6_un1.ip6_un1_nxt=6;

		/*Determine if computed length is reasonable*/
		if(nnew.length > 0xFFFF){
				dbgprintf(1, "Error: Given TCP data length is too large for an IPv6 packet!\n");
				return 0;
		}

		/*Adjust IPv6 header to account for packet's total length*/
		iph->ip6_ctlun.ip6_un1.ip6_un1_plen=htons(nnew.length);

		/*Adjust length*/
		new->length=nnew.length + sizeof(struct ip6_hdr);

		/*Cleanup*/
		free(nnew.dest_id);
		free(nnew.src_id);
return 1;
}

/*IPv4 Encapsulation*/
int ipv4_encap(struct packet *new, const struct const_packet *old)
{
		struct iphdr 		*iph;
		struct packet		nnew;
		struct const_packet	nold;

		/*Safety checks*/
		if(!new || !old || !new->data || !old->data || !new->h || !old->h){
			dbgprintf(0,"Error: IPv4 Encapsulation Function given bad data!\n");
			return 0;
		}
		if(old->length < sizeof(struct iphdr) || new->length < sizeof(struct iphdr)){
			dbgprintf(0, "Error: IPv4 Encapsulation Function given packet of wrong size!\n");
			return 0;
		}

		/*Copy IPv4 header over*/
		memcpy(new->data, old->data, sizeof(struct iphdr));

		/*Cast Pointer*/
		iph=(struct iphdr*)(new->data);

		/*Adjust pointers and lengths*/
		nold.data= old->data +iph->ihl*4;
		nnew.data= new->data +iph->ihl*4;
		nold.length= old->length -iph->ihl*4;
		nnew.length= new->length -iph->ihl*4;
		nnew.h=new->h;
		nold.h=old->h;

		/*Confirm that this is IPv4*/
		if(iph->version!=4){
			dbgprintf(1, "Note: Packet is not IPv4\n");
			return 0;
		}

		/*Select Next Protocol*/
		switch(iph->protocol){
			case 33:
					/*DCCP*/
					nnew.id_len=4;
					nnew.src_id=malloc(nnew.id_len);
					nnew.dest_id=malloc(nnew.id_len);
					if(nnew.src_id==NULL||nnew.dest_id==NULL){
						dbgprintf(0,"Error: Couldn't allocate Memory\n");
						exit(1);
					}
					memcpy(nnew.src_id,&iph->saddr,nnew.id_len);
					memcpy(nnew.dest_id,&iph->daddr,nnew.id_len);
					if(!convert_packet(&nnew, &nold)){
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
		new->length=nnew.length + iph->ihl*4;

		/*Determine if computed length is reasonable*/
		if(nnew.length > 0xFFFF){
				dbgprintf(1, "Error: Given TCP header+data length is too large for an IPv4 packet!\n");
				return 0;
		}

		/*Adjust IPv4 header to account for packet's total length*/
		iph->tot_len=htons(new->length);

		/*Compute IPv4 Checksum*/
		iph->check=0;
		iph->check=ipv4_chksum(new->data,iph->ihl*4);

		/*Cleanup*/
		free(nnew.src_id);
		free(nnew.dest_id);
return 1;
}

int linux_cooked_encap(struct packet *new, const struct const_packet *old)
{
	struct sll_header		*slh;
	struct packet			nnew;
	struct const_packet		nold;


	/*Safety checks*/
	if(!new|| !old || !new->data || !old->data || !new->h || !old->h){
		dbgprintf(0,"Error: SLL Encapsulation Function given bad data!\n");
		return 0;
	}
	if(old->length < sizeof(struct sll_header) || new->length < sizeof(struct sll_header)){
		dbgprintf(0, "Error: SLL Encapsulation Function given packet of wrong size!\n");
		return 0;
	}

	/*Copy SLL header over*/
	memcpy(new->data, old->data, sizeof(struct sll_header));

	/*Cast Pointer*/
	slh=(struct sll_header*)(new->data);

	/*Adjust pointers and lengths*/
	nold.data= old->data + sizeof(struct sll_header);
	nnew.data= new->data + sizeof(struct sll_header);
	nold.length= old->length - sizeof(struct sll_header);
	nnew.length= new->length- sizeof(struct sll_header);
	nnew.h=new->h;
	nold.h=old->h;

	/*Confirm that this is SLL*/
	if(ntohs(slh->sll_pkttype) > 4){
		dbgprintf(1, "Note: Packet is not SLL (Linux Cooked Capture)\n");
		return 0;
	}

	/*Select Next Protocol*/
	switch(ntohs(slh->sll_protocol)){
		case ETHERTYPE_IP:
				if(!ipv4_encap(&nnew, &nold)){
						return 0;
				}
				break;
		case ETHERTYPE_IPV6:
				if(!ipv6_encap(&nnew, &nold)){
						return 0;
				}
				break;
		default:
				dbgprintf(1, "Unknown Next Protocol at SLL\n");
				return 0;
				break;
	}

	/*Adjust length*/
	new->length=nnew.length + sizeof(struct sll_header);
return 1;
}
