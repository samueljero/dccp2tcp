/******************************************************************************
Utility to convert a DCCP flow to a TCP flow for DCCP analysis via
		tcptrace.

Copyright (C) 2013  Samuel Jero <sj323707@ohio.edu>

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
Date: 02/2013

Notes:
	1)DCCP MUST use 48 bit sequence numbers
	2)DCCP Ack packets show up as TCP packets containing one byte
******************************************************************************/
#include "dccp2tcp.h"


#define DCCP2TCP_VERSION 1.6
#define COPYRIGHT_YEAR 2013


int debug=0;	/*set to 1 to turn on debugging information*/
int yellow=0;	/*tcptrace yellow line as currently acked packet*/
int green=0;	/*tcptrace green line as currently acked packet*/
int sack=0;		/*add TCP SACKS*/


pcap_t*			in;			/*libpcap input file discriptor*/
pcap_dumper_t	*out;		/*libpcap output file discriptor*/
struct connection *chead;	/*connection list*/


void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int handle_request(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2);
int handle_response(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2);
int handle_dataack(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2);
int handle_ack(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2);
int handle_closereq(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2);
int handle_close(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2);
int handle_reset(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2);
int handle_sync(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2);
int handle_syncack(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2);
int handle_data(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2);
int parse_options(const u_char* opt_start, int len, struct hcon* A, struct hcon* B);
int process_feature(const u_char* feat, int len, int confirm, int L, struct hcon* A, struct hcon* B);
void ack_vect2sack(struct hcon *seq, struct tcphdr *tcph, u_char* tcpopts, u_char* dccphdr,
				__be32 dccpack, struct hcon* o_hcn);
void version();
void usage();


/*Parse commandline options and open files*/
int main(int argc, char *argv[])
{
	char ebuf[200];
	char *erbuffer=ebuf;
	char *dfile=NULL;
	char *tfile=NULL;

	/*parse commandline options*/
	if(argc > 9){
		usage();
	}

	/*loop through commandline options*/
	for(int i=1; i < argc; i++){
		if(argv[i][0]!='-' || (argv[i][0]=='-' && strlen(argv[i])==1)){
			if(dfile==NULL  || argv[i][0]=='-'){
				/*assign first non-dash (or only dash) argument to the dccp file*/
				dfile=argv[i];
			}else{
				if(tfile==NULL){
					tfile=argv[i]; /*assign second non-dash argument to the dccp file*/
				}else{
					usage();
				}
			}
		}else{
			if(argv[i][1]=='d' && strlen(argv[i])==2){ /* -d */
				debug++;
			}
			if(argv[i][1]=='y' && strlen(argv[i])==2){ /* -y */
				yellow=1;
			}
			if(argv[i][1]=='g' && strlen(argv[i])==2){ /* -g */
				green=1;
			}
			if(argv[i][1]=='s' && strlen(argv[i])==2){ /* -s */
				sack++;
			}
			if(argv[i][1]=='h' && strlen(argv[i])==2){ /* -h */
				usage();
			}
			if(argv[i][1]=='V' && strlen(argv[i])==2){ /* -V */
				version();
			}
		}
	}
	
	if(dfile==NULL || tfile==NULL){
		usage();
	}

	/*all options validated*/

	if(debug){
		dbgprintf(1,"Debug On\n");
		if(green){
			dbgprintf(1,"Tcptrace green line at highest acknowledgment\n");
		}else{
			dbgprintf(1,"Tcptrace green line at highest acknowledged acknowledgment\n");
		}
		if(yellow){
			dbgprintf(1,"Tcptrace yellow line at highest acknowledgment\n");
		}else{
			dbgprintf(1,"Tcptrace yellow line window value (a made up number)\n");
		}
		if(sack){
			dbgprintf(1,"Adding TCP SACKS\n");
		}
		dbgprintf(1,"Input file: %s\n", dfile);
		dbgprintf(1,"Output file: %s\n", tfile);
	}

	/*attempt to open input file*/
	in=pcap_open_offline(dfile, erbuffer);
	if(in==NULL){
		dbgprintf(0,"Error opening input file\n");
		exit(1);
	}

	/*attempt to open output file*/
	out=pcap_dump_open(in,tfile);
	if(out==NULL){
		dbgprintf(0,"Error opening output file\n");
		exit(1);
	}

	/*process packets*/
	chead=NULL;
	u_char *user=(u_char*)out;
	pcap_loop(in, -1, handle_packet, user);	
	
	/*close files*/
	pcap_close(in);
	pcap_dump_close(out);

	/*Delete all connections*/
	cleanup_connections();
return 0;
}


/*call back function for pcap_loop--do basic packet handling*/
void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	u_char 				*ndata;
	struct pcap_pkthdr 	nh;
	int					link_type;
	struct packet		new;
	struct const_packet	old;

	/*Determine the link type for this packet*/
	link_type=pcap_datalink(in);

	/*create new libpcap header*/
	memcpy(&nh, h, sizeof(struct pcap_pkthdr));

	/*Setup packet structs*/
	old.h=h;
	old.length=h->caplen;
	old.data=bytes;
	old.dest_id=NULL;
	old.src_id=NULL;
	new.h=&nh;
	new.length=MAX_PACKET;
	new.dest_id=NULL;
	new.src_id=NULL;

	/*create buffer for new packet*/
	new.data=ndata=malloc(MAX_PACKET);
	if(ndata==NULL){
		dbgprintf(0,"Error: Couldn't allocate Memory\n");
		exit(1);
	}

	/*make sure the packet is all zero*/
	memset(new.data, 0, MAX_PACKET);
	
	/*do all the fancy conversions*/
	if(!do_encap(link_type, &new, &old)){
		free(ndata);
		return;
	}

	/*save packet*/
	pcap_dump(user,&nh, ndata);

	free(ndata);
return;
}

/*do all the dccp to tcp conversions*/
int convert_packet(struct packet *new, const struct const_packet* old)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	struct hcon					*h1=NULL;
	struct hcon					*h2=NULL;

	/*Safety checks*/
	if(!new || !old || !new->data || !old->data || !new->h || !old->h){
		dbgprintf(0,"Error:  Convert Packet Function given bad data!\n");
		exit(1);
		return 0;
	}
	if(old->length < (sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext))
												|| new->length < sizeof(struct dccp_hdr)){
		dbgprintf(0, "Error: DCCP Packet Too short!\n");
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));

	dbgprintf(2,"Sequence Number: %llu\n", (unsigned long long)
			(((unsigned long)ntohs(dccph->dccph_seq)<<32) + ntohl(dccphex->dccph_seq_low)));

	/*Ensure packet is at least as large as DCCP header*/
	if(old->length < dccph->dccph_doff*4){
		dbgprintf(0, "Error: DCCP Header truncated\n");
		return 0;
	}

	/*Get Hosts*/
	if(get_host(new->src_id, new->dest_id, new->id_len, dccph->dccph_sport,
			dccph->dccph_dport, dccph->dccph_type,&h1, &h2)){
		dbgprintf(0,"Error: Can't Get Hosts!\n");
		return 0;
	}
	if(h1==NULL || h2==NULL){
		dbgprintf(0, "Error: Can't Get Hosts!\n");
		return 0;
	}
	if(h1->state==IGNORE || h2->state==IGNORE){
		dbgprintf(2, "Ignoring packet between %i and %i\n",
						ntohs(dccph->dccph_sport), ntohs(dccph->dccph_dport));
		return 0;
	}

	/*set TCP standard features*/
	tcph->source=dccph->dccph_sport;
	tcph->dest=dccph->dccph_dport;
	tcph->doff=5;
	tcph->check=htonl(0);
	tcph->urg_ptr=0;

	/*Adjust TCP advertised window size*/
	if(!yellow){
		tcph->window=htons(30000);
	}

	/*Process DCCP Packet Types*/
	switch(dccph->dccph_type){
		case DCCP_PKT_REQUEST:
			dbgprintf(2,"Packet Type: Request\n");
			if(!handle_request(new, old, h1, h2)){
				return 0;
			}
			break;
		case DCCP_PKT_RESPONSE:
			dbgprintf(2,"Packet Type: Response\n");
			if(!handle_response(new,old,h1,h2)){
				return 0;
			}
			break;
		case DCCP_PKT_DATA:
			if(!handle_data(new,old,h1,h2)){
				return 0;
			}
			break;
		case DCCP_PKT_DATAACK:
			dbgprintf(2,"Packet Type: DataAck\n");
			if(!handle_dataack(new,old,h1,h2)){
				return 0;
			}
			break;
		case DCCP_PKT_ACK:
			dbgprintf(2,"Packet Type: Ack\n");
			if(!handle_ack(new,old,h1,h2)){
				return 0;
			}
			break;
		case DCCP_PKT_CLOSEREQ:
			dbgprintf(2,"Packet Type: CloseReq\n");
			if(!handle_closereq(new,old,h1,h2)){
				return 0;
			}
			break;
		case DCCP_PKT_CLOSE:
			dbgprintf(2,"Packet Type: Close\n");
			if(!handle_close(new,old,h1,h2)){
				return 0;
			}
			break;
		case DCCP_PKT_RESET:
			dbgprintf(2,"Packet Type: Reset\n");
			if(!handle_reset(new,old,h1,h2)){
				return 0;
			}
			break;
		case DCCP_PKT_SYNC:
			dbgprintf(2,"Packet Type: Sync\n");
			if(!handle_sync(new,old,h1,h2)){
				return 0;
			}
			break;
		case DCCP_PKT_SYNCACK:
			dbgprintf(2,"Packet Type: SyncAck\n");
			if(!handle_syncack(new,old,h1,h2)){
				return 0;
			}
			break;
		default:
			dbgprintf(0,"Invalid DCCP Packet!!\n");
			return 0;
			break;
	}

	/*Compute TCP checksums*/
	if(new->id_len==IP4_ADDR_LEN){
			tcph->check=0;
			tcph->check=ipv4_pseudohdr_chksum(new->data,
					new->length, new->dest_id, new->src_id, 6);
	}else if(new->id_len==IP6_ADDR_LEN){
			tcph->check=0;
			tcph->check=ipv6_pseudohdr_chksum(new->data,
					new->length, new->dest_id, new->src_id, 6);
	}else{
		tcph->check=0;
		dbgprintf(2,"Unknown ID Length, can't do checksums\n");
	}

	return 1;
}

int handle_request(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	int 						datalength;
	int							optlen;
	u_char* 					tcpopt;
	const u_char*				dccpopt;

	/*length check*/
	if(new->length < sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext)+sizeof(struct dccp_hdr_request)){
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));

	/*determine data length*/
	datalength=old->length - dccph->dccph_doff*4;

	/*Process DCCP Options*/
	dccpopt=old->data + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext)+sizeof(struct dccp_hdr_request);
	optlen=dccph->dccph_doff*4 - sizeof(struct dccp_hdr)-sizeof(struct dccp_hdr_ext)-sizeof(struct dccp_hdr_request);
	if(!parse_options(dccpopt,optlen,h1,h2)){
		return 0;
	}

	/*Do conversion*/
	if(yellow){
		tcph->window=htons(0);
	}
	tcph->ack_seq=htonl(0);
	if(h1->state==INIT){
		tcph->seq=htonl(initialize_hcon(h1, ntohl(dccphex->dccph_seq_low)));
	}else{
		tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),datalength, dccph->dccph_type));
	}
	tcph->syn=1;
	tcph->ack=0;
	tcph->fin=0;
	tcph->rst=0;

	/* add Sack-permitted option, if relevant*/
	if(sack){
		tcpopt=(u_char*)(new->data + tcph->doff*4);
		*tcpopt=4;
		tcpopt++;
		*tcpopt=2;
		tcph->doff++;
	}

	/*calculate length*/
	new->length=tcph->doff*4;
	return 1;
}

int handle_response(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	struct dccp_hdr_ack_bits 	*dccphack;
	int							optlen;
	u_char* 					tcpopt;
	const u_char*				dccpopt;

	/*length check*/
	if(new->length < sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext)
					+ sizeof(struct dccp_hdr_ack_bits)+sizeof(struct dccp_hdr_request)){
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));
	dccphack=(struct dccp_hdr_ack_bits*)(old->data+ sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext));

	/*Process DCCP Options*/
	dccpopt=old->data + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) +
			sizeof(struct dccp_hdr_ack_bits) + sizeof(struct dccp_hdr_request);
	optlen=dccph->dccph_doff*4 - sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext)
			- sizeof(struct dccp_hdr_ack_bits) - sizeof(struct dccp_hdr_request);
	if(!parse_options(dccpopt,optlen,h1,h2)){
		return 0;
	}

	/*Do conversion*/
	if(h2->state!=OPEN){
		dbgprintf(0,"Warning: DCCP Response without a Request!!\n");
	}
	tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low),h1));
	h1->high_ack=ntohl(tcph->ack_seq);
	if(yellow){
		tcph->window=htons(0);
	}
	if(h1->state==INIT){
		tcph->seq=htonl(initialize_hcon(h1, ntohl(dccphex->dccph_seq_low)));
	}
	tcph->syn=1;
	tcph->ack=1;
	tcph->fin=0;
	tcph->rst=0;

	/* add Sack-permitted option, if relevant*/
	if(sack){
		tcpopt=(u_char*)(new->data + tcph->doff*4);
		*tcpopt=4;
		*(tcpopt+1)=2;
		tcph->doff++;
	}

	/*calculate length*/
	new->length=tcph->doff*4;
	return 1;
}

int handle_dataack(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	struct dccp_hdr_ack_bits 	*dccphack;
	int 						datalength;
	int							optlen;
	const u_char* 				pd;
	u_char* 					npd;
	const u_char*				dccpopt;

	/*length check*/
	if(new->length < sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits)){
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));
	dccphack=(struct dccp_hdr_ack_bits*)(old->data+ sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext));

	/*determine data length*/
	datalength=old->length - dccph->dccph_doff*4;
	pd=old->data + dccph->dccph_doff*4;

	/*Process DCCP Options*/
	dccpopt=old->data + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits);
	optlen=dccph->dccph_doff*4 - sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext) - sizeof(struct dccp_hdr_ack_bits);
	if(!parse_options(dccpopt,optlen,h1,h2)){
		return 0;
	}

	/*Do Conversion*/
	if(green){
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low),h1));
	}else{
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph),h1));
	}
	h1->high_ack=ntohl(tcph->ack_seq);
	tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),datalength, dccph->dccph_type));
	if(yellow){
		tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(h2, ntohl(dccphack->dccph_ack_nr_low)));
	}
	if(sack){
		if(sack!=2 || interp_ack_vect((u_char*)dccph)){
			ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low),h1);
		}
	}
	tcph->syn=0;
	tcph->ack=1;
	tcph->fin=0;
	tcph->rst=0;

	/*copy data*/
	npd=new->data + tcph->doff*4;
	memcpy(npd, pd, datalength);

	/*calculate length*/
	new->length=tcph->doff*4 + datalength;
	return 1;
}

int handle_ack(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	struct dccp_hdr_ack_bits 	*dccphack;
	int							optlen;
	const u_char*				dccpopt;

	/*length check*/
	if(new->length < sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits)){
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));
	dccphack=(struct dccp_hdr_ack_bits*)(old->data+ sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext));

	/*Process DCCP Options*/
	dccpopt=old->data + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits);
	optlen=dccph->dccph_doff*4 - sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext) - sizeof(struct dccp_hdr_ack_bits);
	if(!parse_options(dccpopt,optlen,h1,h2)){
		return 0;
	}

	/*Do Conversion*/
	if(green){
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low),h1));
	}else{
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph),h1));
	}
	h1->high_ack=ntohl(tcph->ack_seq);
	tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
	if(yellow){
		tcph->window=htons(-interp_ack_vect((u_char*)dccph)*1400);
		if(-interp_ack_vect((u_char*)dccph)*1400 > 65535){
			dbgprintf(0,"Note: TCP Window Overflow @ %d.%d\n", (int)old->h->ts.tv_sec, (int)old->h->ts.tv_usec);
		}
	}
	if(sack){
		if(sack!=2 || interp_ack_vect((u_char*)dccph)){
			ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low),h1);
		}
	}

	tcph->syn=0;
	tcph->ack=1;
	tcph->fin=0;
	tcph->rst=0;

	/*calculate length*/
	new->length=tcph->doff*4 + 1;
	return 1;
}

int handle_closereq(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	struct dccp_hdr_ack_bits 	*dccphack;
	int							optlen;
	const u_char*				dccpopt;

	/*length check*/
	if(new->length < sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits)){
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));
	dccphack=(struct dccp_hdr_ack_bits*)(old->data+ sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext));

	/*Process DCCP Options*/
	dccpopt=old->data + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits);
	optlen=dccph->dccph_doff*4 - sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext) - sizeof(struct dccp_hdr_ack_bits);
	if(!parse_options(dccpopt,optlen,h1,h2)){
		return 0;
	}

	/*Do Conversion*/
	if(green){
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low),h1));
	}else{
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph),h1));
	}
	h1->high_ack=ntohl(tcph->ack_seq);
	tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
	if(yellow){
		tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(h2, ntohl(dccphack->dccph_ack_nr_low)));
	}
	if(sack){
		if(sack!=2 || interp_ack_vect((u_char*)dccph)){
			ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low),h1);
		}
	}

	tcph->syn=0;
	tcph->ack=1;
	tcph->fin=1;
	tcph->rst=0;

	/*calculate length*/
	new->length=tcph->doff*4;
	return 1;
}

int handle_close(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	struct dccp_hdr_ack_bits 	*dccphack;
	int							optlen;
	const u_char*				dccpopt;

	/*length check*/
	if(new->length < sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits)){
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));
	dccphack=(struct dccp_hdr_ack_bits*)(old->data+ sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext));

	/*Process DCCP Options*/
	dccpopt=old->data + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits);
	optlen=dccph->dccph_doff*4 - sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext) - sizeof(struct dccp_hdr_ack_bits);
	if(!parse_options(dccpopt,optlen,h1,h2)){
		return 0;
	}

	/*Do Conversion*/
	update_state(h1,CLOSE);
	if(green){
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low),h1));
	}else{
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph),h1));
	}
	h1->high_ack=ntohl(tcph->ack_seq);
	tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
	if(yellow){
		tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(h2, ntohl(dccphack->dccph_ack_nr_low)));
	}
	if(sack){
		if(sack!=2 || interp_ack_vect((u_char*)dccph)){
			ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low),h1);
		}
	}

	tcph->syn=0;
	tcph->ack=1;
	tcph->fin=1;
	tcph->rst=0;

	/*calculate length*/
	new->length=tcph->doff*4;
	return 1;
}

int handle_reset(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	struct dccp_hdr_ack_bits 	*dccphack;
	int							optlen;
	const u_char*				dccpopt;

	/*length check*/
	if(new->length < sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits)){
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));
	dccphack=(struct dccp_hdr_ack_bits*)(old->data+ sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext));

	/*Process DCCP Options*/
	dccpopt=old->data + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits);
	optlen=dccph->dccph_doff*4 - sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext) - sizeof(struct dccp_hdr_ack_bits);
	if(!parse_options(dccpopt,optlen,h1,h2)){
		return 0;
	}

	/*Do Conversion*/
	if(h2->state==CLOSE){
		update_state(h1,CLOSE);
	}
	if(green){
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low),h1));
	}else{
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph),h1));
	}
	h1->high_ack=ntohl(tcph->ack_seq);
	tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
	if(yellow){
		tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(h2, ntohl(dccphack->dccph_ack_nr_low)));
	}
	if(sack){
		if(sack!=2 || interp_ack_vect((u_char*)dccph)){
			ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low),h1);
		}
	}

	tcph->syn=0;
	tcph->ack=1;
	tcph->fin=1;
	tcph->rst=0;

	/*calculate length*/
	new->length=tcph->doff*4;
	return 1;
}

int handle_sync(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	struct dccp_hdr_ack_bits 	*dccphack;
	int							optlen;
	const u_char*				dccpopt;

	/*length check*/
	if(new->length < sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits)){
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));
	dccphack=(struct dccp_hdr_ack_bits*)(old->data+ sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext));

	/*Process DCCP Options*/
	dccpopt=old->data + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits);
	optlen=dccph->dccph_doff*4 - sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext) - sizeof(struct dccp_hdr_ack_bits);
	if(!parse_options(dccpopt,optlen,h1,h2)){
		return 0;
	}

	/*Do Conversion*/
	if(green){
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low),h1));
	}else{
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph),h1));
	}
	h1->high_ack=ntohl(tcph->ack_seq);
	tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),0,dccph->dccph_type));
	if(yellow){
		tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(h2, ntohl(dccphack->dccph_ack_nr_low)));
	}else{
		tcph->window=htons(0);
	}
	if(sack){
		if(sack!=2 || interp_ack_vect((u_char*)dccph)){
			ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low),h1);
		}
	}

	tcph->syn=0;
	tcph->ack=1;
	tcph->fin=0;
	tcph->rst=0;

	/*calculate length*/
	new->length=tcph->doff*4;
	return 1;
}

int handle_syncack(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	struct dccp_hdr_ack_bits 	*dccphack;
	int							optlen;
	const u_char*				dccpopt;

	/*length check*/
	if(new->length < sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits)){
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));
	dccphack=(struct dccp_hdr_ack_bits*)(old->data+ sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext));

	/*Process DCCP Options*/
	dccpopt=old->data + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits);
	optlen=dccph->dccph_doff*4 - sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext) - sizeof(struct dccp_hdr_ack_bits);
	if(!parse_options(dccpopt,optlen,h1,h2)){
		return 0;
	}

	/*Do Conversion*/
	if(green){
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low),h1));
	}else{
		tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph),h1));
	}
	h1->high_ack=ntohl(tcph->ack_seq);
	tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),0,dccph->dccph_type));
	if(yellow){
		tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(h2, ntohl(dccphack->dccph_ack_nr_low)));
	}else{
		tcph->window=htons(0);
	}
	if(sack){
		if(sack!=2 || interp_ack_vect((u_char*)dccph)){
			ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low),h1);
		}
	}

	tcph->syn=0;
	tcph->ack=1;
	tcph->fin=0;
	tcph->rst=0;

	/*calculate length*/
	new->length=tcph->doff*4;
	return 1;
}

int handle_data(struct packet* new, const struct const_packet* old, struct hcon* h1, struct hcon* h2)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	int 						datalength;
	int							optlen;
	const u_char* 				pd;
	u_char* 					npd;
	const u_char*				dccpopt;

	/*length check*/
	if(new->length < sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext)){
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));

	/*determine data length*/
	datalength=old->length - dccph->dccph_doff*4;
	pd=old->data + dccph->dccph_doff*4;

	/*Process DCCP Options*/
	dccpopt=old->data + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext);
	optlen=dccph->dccph_doff*4 - sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext);
	if(!parse_options(dccpopt,optlen,h1,h2)){
		return 0;
	}

	/*Do conversion*/
	tcph->ack_seq=htonl(h1->high_ack);
	tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),datalength, dccph->dccph_type));
	tcph->syn=0;
	tcph->ack=1;
	tcph->fin=0;
	tcph->rst=0;

	/*copy data*/
	npd=new->data + tcph->doff*4;
	memcpy(npd, pd, datalength);

	/*calculate length*/
	new->length=tcph->doff*4 + datalength;
	return 1;
}

int parse_options(const u_char* opt_start, int len, struct hcon* A, struct hcon* B)
{
	int optlen;
	int length;
	const u_char* opt;

	/*setup pointer to DCCP options and determine how long the options are*/
	optlen=len;
	opt=opt_start;

	/*parse options*/
	while(optlen > 0){
		/*One byte options (no length)*/
		if(*opt< 32){
			optlen--;
			opt++;
			continue;
		}

		/*Check option length*/
		length=*(opt+1);
		if(length > optlen){
			dbgprintf(0, "Warning: Option would extend into packet data\n");
			return 0;
		}
		if(length < 2){
			dbgprintf(0, "Warning: Bad Option!\n");
			return 0;
		}

		/*Ack Vector Option*/
		if(*opt==38 || *opt==39){
			if(B->type==UNKNOWN){
				B->type=CCID2;
				dbgprintf(1,"Half-connection from port %i to %i probably using CCID 2\n",
											ntohs(B->port),ntohs(A->port));
			}
		}

		/*NDP Count Option*/
		if(*opt==37){
			if(B->type==UNKNOWN){
				B->type=CCID3;
				dbgprintf(1,"Half-connection from port %i to %i probably using CCID 3\n",
											ntohs(B->port),ntohs(A->port));
			}
		}

		/*Feature negotation*/
		if(*opt==32){
			/*Change L*/
			if(!process_feature(opt+2,length-2,FALSE,TRUE,A,B)){
				return 0;
			}
		}
		if(*opt==33){
			/*Confirm L*/
			if(!process_feature(opt+2,length-2,TRUE,TRUE,A,B)){
				return 0;
			}
		}
		if(*opt==34){
			/*Change R*/
			if(!process_feature(opt+2,length-2,FALSE,FALSE,A,B)){
				return 0;
			}
		}
		if(*opt==35){
			/*Confirm R*/
			if(!process_feature(opt+2,length-2,TRUE,FALSE,A,B)){
				return 0;
			}
		}

		optlen-=length;
		opt+=length;
	}

	return 1;
}

int process_feature(const u_char* feat, int len, int confirm, int L, struct hcon* A, struct hcon* B)
{
	const u_char* val;
	int ccid;

	val=feat+1;

	switch(*feat){
		case 1:
			/*CCID*/
			if(confirm==TRUE){
				switch(*val){
					case 2:
						ccid=CCID2;
						break;
					case 3:
						ccid=CCID3;
						break;
					default:
						ccid=UNKNOWN;
						break;
				}
				if(L==TRUE){
					B->type=ccid;
					dbgprintf(1,"Half-connection from port %i to %i using CCID %i\n",
							ntohs(B->port),ntohs(A->port), *val);
				}else{
					A->type=ccid;
					dbgprintf(1,"Half-connection from port %i to %i using CCID %i\n",
							ntohs(A->port),ntohs(B->port), *val);
				}
			}
			break;
		case 2:
			/*Short sequence nums*/
			if(confirm==TRUE && *val==1){
				B->type=IGNORE;
				A->type=IGNORE;
				dbgprintf(0,"Error: DCCP is trying to turn on short sequence numbers\n"
						"  for the connection between %i and %i. We do not support this.\n"
						"  This connection will be ignored.",ntohs(A->port),ntohs(B->port));
				return 0;
			}
			break;
	}
	return 1;
}

/*Ack Vector to SACK Option*/
void ack_vect2sack(struct hcon *hcn, struct tcphdr *tcph, u_char* tcpopts, u_char* dccphdr,
																__be32 dccpack, struct hcon* o_hcn)
{
	int hdrlen=((struct dccp_hdr*)dccphdr)->dccph_doff*4;
	int optlen;
	int len;
	int tmp;
	__be32 bp;
	u_char* temp;
	u_char* opt;
	u_char* cur;
	u_char* tlen;
	u_int32_t bL=0;
	u_int32_t bR;
	u_int32_t* pL;
	u_int32_t* pR;
	int num_blocks;
	int cont;
	int isopt;

	/*setup pointer to DCCP options and determine how long the options are*/
	optlen=hdrlen-sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext) - sizeof(struct dccp_hdr_ack_bits);
	opt=dccphdr + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits);

	if(optlen<=0){
		return;
	}

	/*setup tcp pointers*/
	num_blocks=4;
	*tcpopts=5;
	tlen=tcpopts+1;
	temp=tlen;
	temp++;
	pL=(u_int32_t*)temp;
	pR=pL+1;

	/*setup tcp control variables*/
	bp=dccpack;
	cont=0;
	*tlen=2;
	isopt=0;

	/*parse options*/
	while(optlen > 0){

		/*One byte options (no length)*/
		if(*opt< 32){
			optlen--;
			opt++;
			continue;
		}

		len=*(opt+1);
		if(len > optlen){
			dbgprintf(0, "Warning: Option would extend into packet data\n");
			break;
		}

		/*Ack Vector Option*/
		if(*opt==38 || *opt==39){
			tmp=len-2;
			cur=opt+2;
			/*loop through Vector*/
			while(tmp > 0){
				/*ack vector works BACKWARDS through time*/

				if((*cur & 0xC0)==0xC0 || (*cur & 0xC0)==0x40){ //lost packet
					if(cont){ /*end a SACK run, if one is started*/
						bR=convert_ack(hcn, bp,o_hcn);
						cont=0;
						num_blocks--;
						*pR=htonl(bR);
						*pL=htonl(bL);
						tcph->doff+=2;
						*tlen+=8;
						pL=pR+1;
						pR=pL+1;
					}
					bp= bp - (*cur & 0x3F)- 1;
				}

				if((*cur & 0xC0)==0x00){ //received packet
					if(!cont){ /*if no SACK run and we can start another one, do so*/
						if(num_blocks>0){
							bL=convert_ack(hcn, bp, o_hcn);
							isopt=1;
							cont=1;

						}
					}
					bp =  bp -(*cur & 0x3F)- 1;
				}
				tmp--;
				cur++;
			}
		}

		optlen-=len;
		opt+=len;
	}

	/*if we are in the middle of a SACK run, close it*/
	if(cont){
		bR=convert_ack(hcn, bp,o_hcn);
		*pR=htonl(bR);
		*pL=htonl(bL);
		tcph->doff+=2;
		*tlen+=8;
		cont=0;
	}

	/*adjust length if the option is actually added*/
	if(isopt){
		tcph->doff+=1;
	}
return;
}

void version()
{
	dbgprintf(0, "dccp2tcp version %.1f\n",DCCP2TCP_VERSION);
	dbgprintf(0, "Copyright (C) %i Samuel Jero <sj323707@ohio.edu>\n",COPYRIGHT_YEAR);
	dbgprintf(0, "This program comes with ABSOLUTELY NO WARRANTY.\n");
	dbgprintf(0, "This is free software, and you are welcome to\n");
	dbgprintf(0, "redistribute it under certain conditions.\n");
	exit(0);
}

/*Usage information for program*/
void usage()
{
	dbgprintf(0,"Usage: dccp2tcp [-d] [-h] [-V] [-y] [-g] [-s] dccp_file tcp_file\n");
	dbgprintf(0, "          -d   Debug. May be repeated for aditional verbosity.\n");
	dbgprintf(0, "          -V   Version information\n");
	dbgprintf(0, "          -h   Help\n");
	dbgprintf(0, "          -y   Yellow line is highest ACK\n");
	dbgprintf(0, "          -g   Green line is highest ACK\n");
	dbgprintf(0, "          -s   convert ACK Vectors to SACKS\n");
	exit(0);
}

/*Debug Printf*/
void dbgprintf(int level, const char *fmt, ...)
{
    va_list args;
    if(debug>=level){
    	va_start(args, fmt);
    	vfprintf(stderr, fmt, args);
    	va_end(args);
    }
}
