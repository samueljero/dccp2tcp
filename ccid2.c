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
	1)CCID2 ONLY
	2)DCCP MUST use 48 bit sequence numbers
	3)DCCP DATA packets are not implemented (Linux doesn't use them)
	4)DCCP Ack packets show up as TCP packets containing one byte
******************************************************************************/
#include "dccp2tcp.h"

unsigned int interp_ack_vect(u_char* hdr);
u_int32_t initialize_seq(struct host *seq, __be32 initial);
u_int32_t add_new_seq(struct host *seq, __be32 num, int size, enum dccp_pkt_type type);
u_int32_t convert_ack(struct host *seq, __be32 num);
int acked_packet_size(struct host *seq, __be32 num);
void ack_vect2sack(struct host *seq, struct tcphdr *tcph, u_char* tcpopts, u_char* dccphdr, __be32 dccpack);

/*do all the dccp to tcp conversions*/
int ccid2_convert_packet(struct packet *new, const struct const_packet* old)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	struct dccp_hdr_ack_bits 	*dccphack;
	struct host					*h1=NULL;
	struct host					*h2=NULL;
	int 						datalength;
	int							len=0;
	const u_char* 				pd;
	u_char* 					npd;
	u_char* 					tcpopt;

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));
	dccphack=(struct dccp_hdr_ack_bits*)(old->data+ sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext));

	/*Get Hosts*/
	if(get_host(new->src_id, new->dest_id, new->id_len,
			dccph->dccph_sport, dccph->dccph_dport, &h1, &h2)){
		dbgprintf(0,"Error: Can't Get Hosts!\n");
		return 0;
	}
	if(h1==NULL || h2==NULL){
		dbgprintf(0, "Error: Can't Get Hosts!\n");
		return 0;
	}

	/*Ensure packet is at least as large as DCCP header*/
	if(dccph->dccph_type!=DCCP_PKT_DATA &&
			old->length < (sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext) +
			sizeof(struct dccp_hdr_ack_bits))){
		dbgprintf(0, "Error: DCCP Packet Too short!\n");
	}

	/*determine data length*/
	datalength=old->length - dccph->dccph_doff*4;
	pd=old->data + dccph->dccph_doff*4;

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

	/*make changes by packet type*/
	if(dccph->dccph_type==DCCP_PKT_REQUEST){//DCCP REQUEST -->TCP SYN
		dbgprintf(2,"Packet Type: Request\n");
		if(h1->state==INIT){
			if(yellow){
				tcph->window=htons(0);
			}
			tcph->ack_seq=htonl(0);
			tcph->seq=htonl(initialize_seq(h1, ntohl(dccphex->dccph_seq_low)));
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
			len=tcph->doff*4;
		}
	}

	if(dccph->dccph_type==DCCP_PKT_RESPONSE){//DCCP RESPONSE-->TCP SYN,ACK
		dbgprintf(2,"Packet Type: Response\n");
		if(h2->state==OPEN && h1->state==INIT){
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)));
			if(yellow){
				tcph->window=htons(0);
			}
			tcph->seq=htonl(initialize_seq(h1, ntohl(dccphex->dccph_seq_low)));
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
			len=tcph->doff*4;
		}
	}

	if(dccph->dccph_type==DCCP_PKT_DATA){//DCCP DATA----Never seen in packet capture
		dbgprintf(0,"DCCP Data packet not yet implemented\n");
		exit(1);
	}

	if(dccph->dccph_type==DCCP_PKT_DATAACK){//DCCP DATAACK-->TCP ACK with data
		dbgprintf(2,"Packet Type: DataAck\n");
		if(green){
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)));
		}else{
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
		}
		tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),datalength, dccph->dccph_type));
		if(yellow){
			tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(h2, ntohl(dccphack->dccph_ack_nr_low)));
		}
		if(sack){
			if(sack!=2 || interp_ack_vect((u_char*)dccph)){
				ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
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
		len= tcph->doff*4 + datalength;
	}

	if(dccph->dccph_type==DCCP_PKT_ACK){ //DCCP ACK -->TCP ACK with no data
		dbgprintf(2,"Packet Type: Ack\n");
		if(green){
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)));
		}else{
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
		}
		tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
		if(yellow){
			tcph->window=htons(-interp_ack_vect((u_char*)dccph)*1400);
			if(-interp_ack_vect((u_char*)dccph)*1400 > 65535){
				printf("Note: TCP Window Overflow @ %d.%d\n", (int)old->h->ts.tv_sec, (int)old->h->ts.tv_usec);
			}
		}
		if(sack){
			if(sack!=2 || interp_ack_vect((u_char*)dccph)){
				ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
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
		update_state(h1,CLOSE);
		if(green){
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)));
		}else{
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
		}
		tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
		if(yellow){
			tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(h2, ntohl(dccphack->dccph_ack_nr_low)));
		}
		if(sack){
			if(sack!=2 || interp_ack_vect((u_char*)dccph)){
				ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
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
		if(h2->state==CLOSE){
			update_state(h1,CLOSE);
		}
		dbgprintf(2,"Packet Type: Reset\n");
		if(green){
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)));
		}else{
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
		}
		tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),1,dccph->dccph_type));
		if(yellow){
			tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(h2, ntohl(dccphack->dccph_ack_nr_low)));
		}
		if(sack){
			if(sack!=2 || interp_ack_vect((u_char*)dccph)){
				ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
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
		if(green){
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)));
		}else{
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
		}
		tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),0,dccph->dccph_type));
		if(yellow){
			tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(h2, ntohl(dccphack->dccph_ack_nr_low)));
		}else{
			tcph->window=htons(0);
		}
		if(sack){
			if(sack!=2 || interp_ack_vect((u_char*)dccph)){
				ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low) );
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
		if(green){
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)));
		}else{
			tcph->ack_seq=htonl(convert_ack(h2,ntohl(dccphack->dccph_ack_nr_low)+interp_ack_vect((u_char*)dccph)));
		}
		tcph->seq=htonl(add_new_seq(h1, ntohl(dccphex->dccph_seq_low),0,dccph->dccph_type));
		if(yellow){
			tcph->window=htons(-interp_ack_vect((u_char*)dccph)*acked_packet_size(h2, ntohl(dccphack->dccph_ack_nr_low)));
		}else{
			tcph->window=htons(0);
		}
		if(sack){
			if(sack!=2 || interp_ack_vect((u_char*)dccph)){
				ack_vect2sack(h2, tcph, (u_char*)tcph + tcph->doff*4, (u_char*)dccph, ntohl(dccphack->dccph_ack_nr_low));
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

	new->length=len;
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

		/*One byte options (no length)*/
		if(*opt< 32){
			optlen--;
			opt++;
			continue;
		}

		/*Check option length*/
		len=*(opt+1);
		if(len > optlen){
			dbgprintf(0, "Warning: Option would extend into packet data\n");
			return additional;
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

				if(((*cur& 0xC0)!= 0xC0) && ((*cur& 0xC0)!= 0x00) && ((*cur& 0xC0)!= 0x40)){
					dbgprintf(1, "Warning: Invalid Ack Vector!! (Linux will handle poorly!)\n");
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
u_int32_t initialize_seq(struct host *seq, __be32 initial)
{
	/*set default values*/
	seq->cur=0;
	seq->size=TBL_SZ;

	/*allocate table*/
	seq->table=(struct tbl*)malloc(sizeof(struct tbl)*TBL_SZ);
	if(seq->table==NULL){
		dbgprintf(0,"Can't Allocate Memory!\n");
		exit(1);
	}

	/*add first sequence number*/
	seq->table[0].old=initial;
	seq->table[0].new=initial;
	seq->table[0].type=DCCP_PKT_REQUEST;
	seq->table[0].size=0;
	update_state(seq,OPEN);
return initial;
}


/*Convert Sequence Numbers*/
u_int32_t add_new_seq(struct host *seq, __be32 num, int size, enum dccp_pkt_type type)
{
	int prev;
	if(seq==NULL){
		dbgprintf(0,"ERROR NULL POINTER!\n");
		exit(1);
	}

	if(seq->table==NULL){
		dbgprintf(1, "Warning: Connection uninitialized\n");
		return initialize_seq(seq, num);
	}

	/*account for missing packets*/
	if(num - seq->table[seq->cur].old +1 >=100){
			dbgprintf(1,"Missing more than 100 packets!\n");
	}
	while(seq->table[seq->cur].old +1 < num && seq->table[seq->cur].old +1 > 0){
		prev=seq->cur;
		if(num - seq->table[seq->cur].old +1 <100){
			dbgprintf(1,"Missing Packet: %X\n",seq->table[prev].new+1);
		}
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
u_int32_t convert_ack(struct host *seq, __be32 num)
{
	if(seq==NULL){
		dbgprintf(0,"ERROR NULL POINTER!\n");
		exit(1);
	}

	if(seq->table==NULL){
		dbgprintf(1, "Warning: Connection uninitialized\n");
		initialize_seq(seq, num);
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
int acked_packet_size(struct host *seq, __be32 num)
{
	if(seq==NULL){
		dbgprintf(0,"ERROR NULL POINTER!\n");
		exit(1);
	}

	if(seq->table==NULL){
		dbgprintf(1, "Warning: Connection uninitialized\n");
		initialize_seq(seq, num);
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
void ack_vect2sack(struct host *seq, struct tcphdr *tcph, u_char* tcpopts, u_char* dccphdr, __be32 dccpack)
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
