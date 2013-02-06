/******************************************************************************
Utility to convert a DCCP flow to a TCP flow for DCCP analysis via
		tcptrace. Functions for differentiating different DCCP connections.

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
******************************************************************************/
#include "dccp2tcp.h"

int isClosed(struct hcon *A, struct hcon *B, enum dccp_pkt_type pkt_type);

/*Lookup a connection. If it doesn't exist, add a new connection and return it.*/
int get_host(u_char *src_id, u_char* dest_id, int id_len, int src_port, int dest_port,
		enum dccp_pkt_type pkt_type, struct hcon **fwd, struct hcon **rev){
	struct connection *ptr;

	/*Empty list*/
	if(chead==NULL){
		if(add_connection(src_id, dest_id, id_len, src_port, dest_port)==NULL){
			return 1;
		}
		*fwd=&chead->A;
		*rev=&chead->B;
		return 0;
	}

	/*Loop list looking for connection*/
	ptr=chead;
	while(ptr!=NULL){
		if(memcmp(ptr->A.id,src_id,id_len)==0 && ptr->A.port==src_port &&
				!isClosed(&ptr->A, &ptr->B, pkt_type)){
			*fwd=&ptr->A;
			*rev=&ptr->B;
			return 0;
		}
		if(memcmp(ptr->B.id,src_id,id_len)==0 && ptr->B.port==src_port &&
				!isClosed(&ptr->A, &ptr->B, pkt_type)){
			*fwd=&ptr->B;
			*rev=&ptr->A;
			return 0;
		}
		ptr=ptr->next;
	}

	/*Add new connection*/
	ptr=add_connection(src_id, dest_id, id_len, src_port, dest_port);
	if(ptr==NULL){
		return 1;
	}
	*fwd=&ptr->A;
	*rev=&ptr->B;
	return 0;
}

/*Returns true if the connection is closed and any packets should go to
 * a new connection with the same four-tuple*/
int isClosed(struct hcon *A, struct hcon *B, enum dccp_pkt_type pkt_type){
	if(pkt_type==DCCP_PKT_REQUEST || pkt_type==DCCP_PKT_RESPONSE){
		if(A->state==CLOSE && B->state==CLOSE){
			/*We're opening a new connection on hosts/ports we've used before, mark
			 * old connection as dead*/
			A->state=DEAD;
			B->state=DEAD;
			return TRUE;
		}
	}else{
		if(A->state==DEAD || B->state==DEAD){
			return TRUE;
		}
	}
	return FALSE;
}

/*Add a connection. Return it. On failure, return NULL*/
struct connection *add_connection(u_char *src_id, u_char* dest_id, int id_len, int src_port, int dest_port){
	struct connection *ptr;
	struct connection *prev;

	/*Allocate memory*/
	if(chead==NULL){
		ptr=chead=malloc(sizeof(struct connection));
	}else{
		ptr=chead;
		prev=chead;
		while(ptr!=NULL){
			prev=ptr;
			ptr=ptr->next;
		}
		ptr=prev->next=malloc(sizeof(struct connection));
	}

	if(ptr==NULL){
		dbgprintf(0,"Error: Couldn't allocate Memory\n");
		exit(1);
	}

	/*Initialize*/
	ptr->A.id=malloc(id_len);
	ptr->B.id=malloc(id_len);
	if(ptr->A.id==NULL||ptr->B.id==NULL){
		dbgprintf(0,"Error: Couldn't allocate Memory\n");
		exit(1);
	}
	memcpy(ptr->A.id,src_id,id_len);
	ptr->A.port=src_port;
	ptr->A.state=INIT;
	ptr->A.type=UNKNOWN;
	memcpy(ptr->B.id,dest_id,id_len);
	ptr->B.port=dest_port;
	ptr->B.state=INIT;
	ptr->B.type=UNKNOWN;

	return ptr;
}

/*Update the state on a host*/
int update_state(struct hcon* hst, enum con_state st){
	if(!hst){
		return 1;
	}
	hst->state=st;
	return 0;
}

/*Free all connections*/
void cleanup_connections(){
	struct connection *ptr;
	struct connection *prev;
	prev=ptr=chead;

	while(ptr!=NULL){
		prev=ptr;
		free(ptr->A.id);
		free(ptr->B.id);
		ptr=ptr->next;
		free(prev);
	}
return;
}

/* Setup Half Connection Structure*/
u_int32_t initialize_hcon(struct hcon *hcn, d_seq_num initial)
{
	/*set default values*/
	hcn->cur=0;
	hcn->size=TBL_SZ;
	hcn->high_ack=0;

	/*allocate table*/
	hcn->table=(struct tbl*)malloc(sizeof(struct tbl)*TBL_SZ);
	if(hcn->table==NULL){
		dbgprintf(0,"Can't Allocate Memory!\n");
		exit(1);
	}

	/*add first sequence number*/
	hcn->table[0].old=initial;
	hcn->table[0].new=initial;
	hcn->table[0].type=DCCP_PKT_REQUEST;
	hcn->table[0].size=0;
	update_state(hcn,OPEN);
return initial;
}

/*Convert Sequence Numbers*/
u_int32_t add_new_seq(struct hcon *hcn, d_seq_num num, int size, enum dccp_pkt_type type)
{
	int prev;
	if(hcn==NULL){
		dbgprintf(0,"ERROR NULL POINTER!\n");
		exit(1);
	}

	if(hcn->table==NULL){
		dbgprintf(1, "Warning: Connection uninitialized\n");
		return initialize_hcon(hcn, num);
	}

	/*account for missing packets*/
	if(num - hcn->table[hcn->cur].old +1 >=100){
			dbgprintf(1,"Missing more than 100 packets!\n");
	}
	while(hcn->table[hcn->cur].old +1 < num && hcn->table[hcn->cur].old +1 > 0){
		prev=hcn->cur;
		if(num - hcn->table[hcn->cur].old +1 <100){
			dbgprintf(1,"Missing Packet %i\n",hcn->table[prev].new+1);
		}
		hcn->cur=(hcn->cur+1)%(hcn->size);/*find next available table slot*/
		hcn->table[hcn->cur].old=hcn->table[prev].old+1;
		hcn->table[hcn->cur].new=hcn->table[prev].new + hcn->table[prev].size;
		hcn->table[hcn->cur].size=size;
		hcn->table[hcn->cur].type=type;
	}

	prev=hcn->cur;
	hcn->cur=(hcn->cur+1)%(hcn->size);/*find next available table slot*/
	hcn->table[hcn->cur].old=num;
	hcn->table[hcn->cur].size=size;
	hcn->table[hcn->cur].type=type;
	if(hcn->table[prev].type==DCCP_PKT_REQUEST || hcn->table[prev].type==DCCP_PKT_RESPONSE){
		hcn->table[hcn->cur].new=hcn->table[prev].new + hcn->table[prev].size;
		hcn->table[hcn->cur].size=1;
		return hcn->table[prev].new + hcn->table[prev].size+1;
	}
	if(type==DCCP_PKT_DATA || type==DCCP_PKT_DATAACK || type==DCCP_PKT_ACK){
		hcn->table[hcn->cur].new=hcn->table[prev].new + hcn->table[prev].size;
		return hcn->table[hcn->cur].new+1;
	}
	if(type==DCCP_PKT_SYNC || type==DCCP_PKT_SYNCACK){
		hcn->table[hcn->cur].new=hcn->table[prev].new + hcn->table[prev].size;
		return hcn->table[hcn->cur].new;
	}
	hcn->table[hcn->cur].new=hcn->table[prev].new + hcn->table[prev].size;
return hcn->table[hcn->cur].new +1;
}

/*Convert Ack Numbers*/
u_int32_t convert_ack(struct hcon *hcn, d_seq_num num, struct hcon *o_hcn)
{
	if(hcn==NULL){
		dbgprintf(0,"ERROR NULL POINTER!\n");
		exit(1);
	}

	if(hcn->table==NULL){
		dbgprintf(1, "Warning: Connection uninitialized\n");
		initialize_hcon(hcn, num);
	}

	/*loop through table looking for the DCCP ack number*/
	for(int i=0; i < hcn->size; i++){
		if(hcn->table[i].old==num){
			return 	hcn->table[i].new + hcn->table[i].size + 1; /*TCP acks the sequence number plus 1*/
		}
	}

	dbgprintf(1, "Error: Sequence Number Not Found! looking for %i. Using highest ACK, %i, instead.\n",
																						num, o_hcn->high_ack);
return o_hcn->high_ack;
}

/* Get size of packet being acked*/
int acked_packet_size(struct hcon *hcn, d_seq_num num)
{
	if(hcn==NULL){
		dbgprintf(0,"ERROR NULL POINTER!\n");
		exit(1);
	}

	if(hcn->table==NULL){
		dbgprintf(1, "Warning: Connection uninitialized\n");
		initialize_hcon(hcn, num);
	}

	/*loop through table looking for the DCCP ack number*/
	for(int i=0; i < hcn->size; i++){
		if(hcn->table[i].old==num){
			return 	hcn->table[i].size;
		}
	}

	dbgprintf(1, "Error: Sequence Number Not Found! looking for %i\n", num);
return 0;
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

	if(optlen<=0){
		return 0;
	}

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
