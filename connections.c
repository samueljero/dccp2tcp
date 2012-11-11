/******************************************************************************
Utility to convert a DCCP flow to a TCP flow for DCCP analysis via
		tcptrace. Functions for differentiating different DCCP connections.

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

Notes:
	1)CCID2 ONLY
	2)DCCP MUST use 48 bit sequence numbers
	3)Checksums are not computed (they are zeroed)
	4)DCCP DATA packets are not implemented (Linux doesn't use them)
	5)DCCP Ack packets show up as TCP packets containing one byte
******************************************************************************/
#include "dccp2tcp.h"

/*Lookup a connection. If it doesn't exist, add a new connection and return it.*/
int get_host(u_char *src_id, u_char* dest_id, int id_len, int src_port, int dest_port,
		struct host **fwd, struct host **rev){
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
				!(ptr->A.state==CLOSE && ptr->B.state==CLOSE)){
			*fwd=&ptr->A;
			*rev=&ptr->B;
			return 0;
		}
		if(memcmp(ptr->B.id,src_id,id_len)==0 && ptr->B.port==src_port &&
				!(ptr->B.state==CLOSE && ptr->A.state==CLOSE)){
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
	memcpy(ptr->B.id,dest_id,id_len);
	ptr->B.port=dest_port;
	ptr->B.state=INIT;

	return ptr;
}

/*Update the state on a host*/
int update_state(struct host* hst, enum con_state st){
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
