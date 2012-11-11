/******************************************************************************
Author: Samuel Jero

Date: 11/2012

Description: Functions for differentiating different DCCP connections.

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
