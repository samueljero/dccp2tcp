/******************************************************************************
Author: Samuel Jero

Date: 5/2011

Description: Program to convert a DCCP flow to a TCP flow for DCCP analysis via
		tcptrace.

Notes:
	1)Supports only a single DCCP contection per capture
	2)Source Port!=Destination Port
	3)DCCP MUST use 48 bit sequence numbers
	4)Checksums are not computed (they are zeroed)
	5)Only implements those packet types normally used in a session
	6)DCCP Ack packets show up as TCP packets containing one byte
	7)Very little error checking of packet headers
******************************************************************************/
#include "dccp2tcp.h"


int debug=0;	/*set to 1 to turn on debugging information*/
int yellow=0;	/*tcptrace yellow line as currently acked packet*/
int green=0;	/*tcptrace green line as currently acked packet*/
int sack=0;		/*add TCP SACKS*/

pcap_t*			in;			/*libpcap input file discriptor*/
pcap_dumper_t	*out;	/*libpcap output file discriptor*/
struct seq_num	*s1;	/*sequence number structure for side one of connection*/
struct seq_num	*s2;	/*sequence number structure for side two of connection*/



void PcapSavePacket(struct pcap_pkthdr *h, u_char *data);
void process_packets();
void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int convert_packet(struct pcap_pkthdr *h, u_char **nptr, int *nlength, const u_char **optr, int *length);
unsigned int interp_ack_vect(u_char* hdr);
u_int32_t initialize_seq(struct seq_num **seq, __be16 source, __be32 initial);
u_int32_t add_new_seq(struct seq_num *seq, __be32 num, int size, enum dccp_pkt_type type);
u_int32_t convert_ack(struct seq_num *seq, __be32 num);
int acked_packet_size(struct seq_num *seq, __be32 num);
void ack_vect2sack(struct seq_num *seq, struct tcphdr *tcph, u_char* tcpopts, u_char* dccphdr, __be32 dccpack);


/*Parse commandline options and open files*/
int main(int argc, char *argv[])
{
	char ebuf[200];
	char *erbuffer=ebuf;
	char *dfile=NULL;
	char *tfile=NULL;

	/*parse commandline options*/
	if(argc<3 || argc > 9){
		dbgprintf(0, "Usage: dccp2tcp dccp_file tcp_file [-d] [-y] [-g] [-s]\n");
		exit(1);
	}

	/*loop through commandline options*/
	for(int i=1; i < argc; i++){
		if(argv[i][0]!='-'){
			if(dfile==NULL){ /*assign first non-dash argument to the dccp file*/
				dfile=argv[i];
			}else{
				if(tfile==NULL){
					tfile=argv[i]; /*assign second non-dash argument to the dccp file*/
				}else{
					dbgprintf(0,"Usage: dccp2tcp dccp_file tcp_file [-d] [-y] [-g] [-s]\n");
					exit(1);
				}
			}
		}else{
			if(argv[i][1]=='d' && strlen(argv[i])==2){ /*debug option*/
				debug++;
			}
			if(argv[i][1]=='y' && strlen(argv[i])==2){ /*yellow option*/
				yellow=1;
			}
			if(argv[i][1]=='g' && strlen(argv[i])==2){ /*green option*/
				green=1;
			}
			if(argv[i][1]=='s' && strlen(argv[i])==2){ /*sack option*/
				sack++;
			}
		}
	}
	
	if(dfile==NULL || tfile==NULL){
		dbgprintf(0,"Usage: dccp2tcp dccp_file tcp_file [-d] [-y] [-g] [-s]\n");
		exit(1);
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
	u_char *user=(u_char*)out;
	pcap_loop(in, -1, handle_packet, user);	
	
	/*close files*/
	pcap_close(in);
	pcap_dump_close(out);
return 0;
}


/*call back function for pcap_loop--do basic packet handling*/
void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	u_char 				*ndata;
	u_char 				*nptr;
	int					length;
	int					nlength;
	struct pcap_pkthdr 	nh;
	int					link_type;

	/*Determine the link type for this packet*/
	link_type=pcap_datalink(in);

	/*create new libpcap header*/
	memcpy(&nh, h, sizeof(struct pcap_pkthdr));
	length=h->caplen;
	nlength=MAX_PACKET;

	/*create buffer for new packet*/
	nptr=ndata=malloc(MAX_PACKET);
	if(ndata==NULL){
		dbgprintf(0,"Error: Couldn't allocate Memory\n");
		exit(1);
	}

	/*make sure the packet is all zero*/
	memset(nptr, 0, MAX_PACKET);
	
	/*do all the fancy conversions*/
	if(!do_encap(link_type, &nh, &nptr, &nlength, &bytes, &length)){
		free(ndata);
		return;
	}

	/*save packet*/
	pcap_dump(user,&nh, ndata);

	free(ndata);
return;
}


/*do all the dccp to tcp conversions*/
int convert_packet(struct pcap_pkthdr *h, u_char **nptr, int *nlength, const u_char **optr, int *length)
{	
	u_char* ncur=*nptr;
	const u_char* ocur=*optr;
	struct tcphdr *tcph;
	struct dccp_hdr *dccph;
	struct dccp_hdr_ext *dccphex;
	struct dccp_hdr_ack_bits *dccphack;
	int datalength;
	int	len=0;
	const u_char* pd;
	u_char* npd;
	u_char* tcpopt;

	/*cast header pointers*/
	tcph=(struct tcphdr*)ncur;
	tcpopt=ncur+ sizeof(struct tcphdr);
	dccph=(struct dccp_hdr*)ocur;
	dccphex=(struct dccp_hdr_ext*)(ocur+sizeof(struct dccp_hdr));
	dccphack=(struct dccp_hdr_ack_bits*)(ocur+ sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext));

	dbgprintf(2,"Sequence Number: %llu\n", (unsigned long long)(((unsigned long)ntohs(dccph->dccph_seq)<<32) + ntohl(dccphex->dccph_seq_low)));

	/*determine data length*/
	datalength=*length - dccph->dccph_doff*4;
	pd=*optr + dccph->dccph_doff*4;

	/*set tcp standard features*/
	tcph->source=dccph->dccph_sport;
	tcph->dest=dccph->dccph_dport;
	tcph->doff=5;
	tcph->check=htonl(0);
	tcph->urg_ptr=0;

	/*Adjust TCP advertised window size*/
	if(!yellow){
		tcph->window=htons(30000);
	}

	/*Only accept the first connection*/
	if(s1 && s2 && dccph->dccph_sport!=s1->addr && dccph->dccph_dport!=s1->addr){
		return 0;
	}

	/*make changes by packet type*/
	if(dccph->dccph_type==DCCP_PKT_REQUEST){//DCCP REQUEST -->TCP SYN
		dbgprintf(2,"Packet Type: Request\n");
		if(!s1){
			if(yellow){
				tcph->window=htons(0);
			}
			tcph->ack_seq=htonl(0);
			tcph->seq=htonl(initialize_seq(&s1, dccph->dccph_sport, ntohl(dccphex->dccph_seq_low)));
			tcph->syn=1;
			tcph->ack=0;
			tcph->fin=0;
			tcph->rst=0;

			/* add Sack-permitted option, if relevant*/
			if(sack){
				*tcpopt=4;
				tcpopt++;
				*tcpopt=2;
				tcph->doff++;
			}

			/*calculate length*/
			len=tcph->doff*4;
		}
	}

	if(dccph->dccph_type==DCCP_PKT_RESPONSE){//DCCP RESPONSE-->TCP SYN,ACK
		dbgprintf(2,"Packet Type: Response\n");
		if(s1 && !s2){
			tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)));
			if(yellow){
				tcph->window=htons(0);
			}
			tcph->seq=htonl(initialize_seq(&s2, dccph->dccph_sport, ntohl(dccphex->dccph_seq_low)));
			tcph->syn=1;
			tcph->ack=1;
			tcph->fin=0;
			tcph->rst=0;

			/* add Sack-permitted option, if relevant*/
			if(sack){
				*tcpopt=4;
				*(tcpopt+1)=2;
				tcph->doff++;
			}

			/*calculate length*/
			len=tcph->doff*4;
		}
	}

	if(dccph->dccph_type==DCCP_PKT_DATA){//DCCP DATA----Never seen in packet capture
		dbgprintf(0,"DCCP Data packet not yet implemented\n");
		exit(1);
	}

	if(dccph->dccph_type==DCCP_PKT_DATAACK){//DCCP DATAACK-->TCP ACK with data
		dbgprintf(2,"Packet Type: DataAck\n");
		if(s1 && s2 && dccph->dccph_sport==s1->addr){ //determine which side of connection is sending this packet
			if(green){
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s1, ntohl(dccphex->dccph_seq_low),datalength, dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(s2, ntohl(dccphack->dccph_ack_nr_low)));
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s2, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
				}
			}
		}else if(s1 && s2 && dccph->dccph_sport==s2->addr){
			if(green){
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s2, ntohl(dccphex->dccph_seq_low),datalength,dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(s1, ntohl(dccphack->dccph_ack_nr_low)));
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s2, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );

				}
			}
		}

		tcph->syn=0;
		tcph->ack=1;
		tcph->fin=0;
		tcph->rst=0;

		/*copy data*/
		npd=*nptr + tcph->doff*4;
		memcpy(npd, pd, datalength);

		/*calculate length*/
		len= tcph->doff*4 + datalength;
	}

	if(dccph->dccph_type==DCCP_PKT_ACK){ //DCCP ACK -->TCP ACK with no data
		dbgprintf(2,"Packet Type: Ack\n");
		if(s1 && s2 && dccph->dccph_sport==s1->addr){//determine which side of connection is sending this packet
			if(green){
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s1, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*1400);
				if(-interp_ack_vect((u_char*)dccph)*1400 > 65535){
					printf("Note: TCP Window Overflow @ %d.%d\n", (int)h->ts.tv_sec, (int)h->ts.tv_usec);
				}
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s2, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
				}
			}
		}else if(s1 && s2 && dccph->dccph_sport==s2->addr){
			if(green){
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s2, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*1400);
				if(-interp_ack_vect((u_char*)dccph)*1400 > 65535){
					printf("Note: TCP Window Overflow @ %d.%d\n", (int)h->ts.tv_sec, (int)h->ts.tv_usec);
				}
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s1, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
				}
			}
		}

		tcph->syn=0;
		tcph->ack=1;
		tcph->fin=0;
		tcph->rst=0;

		/*calculate length*/
		len=tcph->doff*4 + 1;
	}

	if(dccph->dccph_type==DCCP_PKT_CLOSEREQ){//DCCP CLOSEREQ----Never seen in packet capture
		dbgprintf(0,"DCCP CloseReq not yet implemented\n");
		exit(1);
	}

	if(dccph->dccph_type==DCCP_PKT_CLOSE){//DCCP CLOSE-->TCP FIN,ACK
		dbgprintf(2,"Packet Type: Close\n");
		if(s1 && s2 && dccph->dccph_sport==s1->addr){//determine which side of connection is sending this packet
			if(green){
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s1, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(s2, ntohl(dccphack->dccph_ack_nr_low)));
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s2, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
				}
			}
		}else if(s1 && s2 && dccph->dccph_sport==s2->addr){
			if(green){
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s2, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(s1, ntohl(dccphack->dccph_ack_nr_low)));
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s1, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
				}
			}
		}

		tcph->syn=0;
		tcph->ack=1;
		tcph->fin=1;
		tcph->rst=0;

		/*calculate length*/
		len=tcph->doff*4;
	}

	if(dccph->dccph_type==DCCP_PKT_RESET){//DCCP RESET-->TCP FIN,ACK (only seen at end of connection as CLOSE ACK)
		dbgprintf(2,"Packet Type: Reset\n");
		if(s1 && s2 && dccph->dccph_sport==s1->addr){//determine which side of connection is sending this packet
			if(green){
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s1, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(s2, ntohl(dccphack->dccph_ack_nr_low)));
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s2, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
				}
			}
		}else if(s1 && s2 && dccph->dccph_sport==s2->addr){
			if(green){
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s2, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(s1, ntohl(dccphack->dccph_ack_nr_low)));
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s1, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
				}
			}
		}

		tcph->syn=0;
		tcph->ack=1;
		tcph->fin=1;
		tcph->rst=0;

		/*calculate length*/
		len=tcph->doff*4;
	}

	if(dccph->dccph_type==DCCP_PKT_SYNC){//DCCP SYNC
		dbgprintf(2,"Packet Type: Sync\n");
		if(s1 && s2 && dccph->dccph_sport==s1->addr){//determine which side of connection is sending this packet
			if(green){
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s1, ntohl(dccphex->dccph_seq_low),0,dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(s2, ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->window=htons(0);
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s2, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
				}
			}
		}else if(s1 && s2 && dccph->dccph_sport==s2->addr){
			if(green){
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s2, ntohl(dccphex->dccph_seq_low),0,dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(s1, ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->window=htons(0);
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s1, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
				}
			}
		}

		tcph->syn=0;
		tcph->ack=1;
		tcph->fin=0;
		tcph->rst=0;

		/*calculate length*/
		len=tcph->doff*4;
	}

	if(dccph->dccph_type==DCCP_PKT_SYNCACK){//DCCP SYNACK
		dbgprintf(2,"Packet Type: SyncAck\n");
		if(s1 && s2 && dccph->dccph_sport==s1->addr){//determine which side of connection is sending this packet
			if(green){
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s1, ntohl(dccphex->dccph_seq_low),0,dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(s2, ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->window=htons(0);
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s2, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low));
				}
			}
		}else if(s1 && s2 && dccph->dccph_sport==s2->addr){
			if(green){
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->ack_seq=htonl(convert_ack(s1,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
			}
			tcph->seq=htonl(add_new_seq(s2, ntohl(dccphex->dccph_seq_low),0,dccph->dccph_type));
			if(yellow){
				tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(s1, ntohl(dccphack->dccph_ack_nr_low)));
			}else{
				tcph->window=htons(0);
			}
			if(sack){
				if(sack!=2 || interp_ack_vect((u_char*)dccph)){
					ack_vect2sack(s1, tcph, tcpopt, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
				}
			}
		}

		tcph->syn=0;
		tcph->ack=1;
		tcph->fin=0;
		tcph->rst=0;

		/*calculate length*/
		len=tcph->doff*4;
	}

	if(dccph->dccph_type==DCCP_PKT_INVALID){//DCCP INVALID----Never seen in packet capture
		dbgprintf(0,"Invalid DCCP Packet!!\n");
		return 0;
	}

	*nlength=len;
return 1;
}


/*Parse Ack Vector Options
 * Returns the Number of packets since last recorded loss*/
unsigned int interp_ack_vect(u_char* hdr)
{
	int hdrlen=((struct dccp_hdr*)hdr)->dccph_doff*4;
	//struct dccp_hdr_ext* e=(struct dccp_hdr_ext*)hdr + sizeof(struct dccp_hdr);
	int optlen;
	int len;
	int tmp;
	int bp=0;
	int additional=0;
	u_char* opt;
	u_char* cur;

	/*setup pointer to DCCP options and determine how long the options are*/
	optlen=hdrlen-sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext) - sizeof(struct dccp_hdr_ack_bits);
	opt=hdr + sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) + sizeof(struct dccp_hdr_ack_bits);

	/*parse options*/
	while(optlen > 0){
		len=*(opt+1);

		/*One byte options (no length)*/
		if(*opt< 32){
			optlen--;
			opt++;
			continue;
		}

		/*Ack Vector Option*/
		if(*opt==38 || *opt==39){
			tmp=len-2;
			cur=opt+2;
			/*loop through Vector*/
			while(tmp > 0){
				/*ack vector works BACKWARDS through time*/

				/*keep track of total packets recieved and if
				a packet is lost, subtract all packets received
				after that*/
				if((*cur & 0xC0)==0xC0 || (*cur & 0xC0)==0x40){ //lost packet
					bp+=(*cur & 0x3F)+1;
					additional= -bp;
				}
					
				if((*cur & 0xC0)==0x00){ //received packet
					bp+= (*cur & 0x3F)+1;
				}
				tmp--;
				cur++;
			}
		}
		
		optlen-=len;
		opt+=len;
	}

	dbgprintf(2,"Ack vector adding: %i\n", additional);
return additional;
}


/* Setup Sequence Number Structure*/
u_int32_t initialize_seq(struct seq_num **seq, __be16 source, __be32 initial)
{
	/*allocate structure*/
	*seq=(struct seq_num*)malloc(sizeof(struct seq_num));
	if(*seq==NULL){
		dbgprintf(0,"Can't Allocate Memory!\n");
		exit(1);
	}

	/*set default values*/
	(*seq)->cur=0;
	(*seq)->addr=source;
	(*seq)->size=TBL_SZ;
	
	/*allocate table*/
	(*seq)->table=(struct tbl*)malloc(sizeof(struct tbl)*TBL_SZ);
	if((*seq)->table==NULL){
		dbgprintf(0,"Can't Allocate Memory!\n");
		exit(1);
	}

	/*add first sequence number*/
	(*seq)->table[0].old=initial;
	(*seq)->table[0].new=initial;
	(*seq)->table[0].type=DCCP_PKT_REQUEST;
	(*seq)->table[0].size=0;
return initial;
}


/*Convert Sequence Numbers*/
u_int32_t add_new_seq(struct seq_num *seq, __be32 num, int size, enum dccp_pkt_type type)
{
	int prev;
	if(seq==NULL){
		dbgprintf(0,"ERROR NULL POINTER!\n");
		exit(1);
	}
	
	/*account for missing packets*/
	while(seq->table[seq->cur].old +1 < num && seq->table[seq->cur].old +1 > 0){
		prev=seq->cur;
		dbgprintf(1,"Missing Packet: %X\n",seq->table[prev].new+1);
		seq->cur=(seq->cur+1)%(seq->size);/*find next available table slot*/
		seq->table[seq->cur].old=seq->table[prev].old+1;
		seq->table[seq->cur].new=seq->table[prev].new + seq->table[prev].size;
		seq->table[seq->cur].size=size;
		seq->table[seq->cur].type=type;
	}

	prev=seq->cur;
	seq->cur=(seq->cur+1)%(seq->size);/*find next available table slot*/
	seq->table[seq->cur].old=num;
	seq->table[seq->cur].size=size;
	seq->table[seq->cur].type=type;
	if(seq->table[prev].type==DCCP_PKT_REQUEST || seq->table[prev].type==DCCP_PKT_RESPONSE){
		seq->table[seq->cur].new=seq->table[prev].new + seq->table[prev].size;
		seq->table[seq->cur].size=1;
		return seq->table[prev].new + seq->table[prev].size+1;
	}
	if(type==DCCP_PKT_DATA || type==DCCP_PKT_DATAACK || type==DCCP_PKT_ACK){
		seq->table[seq->cur].new=seq->table[prev].new + seq->table[prev].size;
		return seq->table[seq->cur].new+1;
	}
	if(type==DCCP_PKT_SYNC || type==DCCP_PKT_SYNCACK){
		seq->table[seq->cur].new=seq->table[prev].new + seq->table[prev].size;
		return seq->table[seq->cur].new;
	}
	seq->table[seq->cur].new=seq->table[prev].new + seq->table[prev].size;
return seq->table[seq->cur].new +1;
}


/*Convert Ack Numbers*/
u_int32_t convert_ack(struct seq_num *seq, __be32 num)
{
	if(seq==NULL){
		dbgprintf(0,"ERROR NULL POINTER!\n");
		exit(1);
	}

	/*loop through table looking for the DCCP ack number*/
	for(int i=0; i < seq->size; i++){
		if(seq->table[i].old==num){
			return 	seq->table[i].new + seq->table[i].size + 1; /*TCP acks the sequence number plus 1*/
		}
	}
	
	dbgprintf(1, "Error: Address Not Found! looking for: %X\n", num);
return 0;
}


/* Get size of packet being acked*/
int acked_packet_size(struct seq_num *seq, __be32 num)
{
	if(seq==NULL){
		dbgprintf(0,"ERROR NULL POINTER!\n");
		exit(1);
	}

	/*loop through table looking for the DCCP ack number*/
	for(int i=0; i < seq->size; i++){
		if(seq->table[i].old==num){
			return 	seq->table[i].size;
		}
	}
	
	dbgprintf(1, "Error: Address Not Found! looking for: %X\n", num);
return 0;
}


/*Ack Vector to SACK Option*/
void ack_vect2sack(struct seq_num *seq, struct tcphdr *tcph, u_char* tcpopts, u_char* dccphdr, __be32 dccpack)
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

	/*setup tcp pointers*/
	num_blocks=2;
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
		len=*(opt+1);

		/*One byte options (no length)*/
		if(*opt< 32){
			optlen--;
			opt++;
			continue;
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
						bR=convert_ack(seq, bp);
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
							bL=convert_ack(seq, bp);
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
		bR=convert_ack(seq, bp);
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
