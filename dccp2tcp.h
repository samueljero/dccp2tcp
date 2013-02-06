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
#ifndef _DCCP2TCP_H
#define _DCCP2TCP_H

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <ctype.h>
#include <pcap.h>
#include <linux/dccp.h>
#include "checksums.h"


#define MAX_PACKET 	1600	/*Maximum size of TCP packet */
#define	TBL_SZ		40000	/*Size of Sequence Number Table*/

#define TRUE 1
#define FALSE 0

/*Packet structure*/
struct packet{
	struct pcap_pkthdr	*h;		/*libpcap header*/
	u_char				*data;	/*Packet Data*/
	int					length;	/*Packet length*/
	int					id_len; /*Length of IDs*/
	u_char				*src_id; /*Source ID of packet*/
	u_char				*dest_id;/*Destination ID of packet*/
};

/*Constant Packet structure*/
struct const_packet{
	const struct pcap_pkthdr *h;	/*libpcap header*/
	const u_char			*data;	/*Packet Data*/
	int						length;	/*Packet length*/
	int						id_len; /*Length of IDs*/
	u_char					*src_id; /*Source ID of packet*/
	u_char					*dest_id;/*Destination ID of packet*/
};

/*Connection states*/
enum con_state{
	INIT,
	OPEN,
	CLOSE,
	DEAD,
	IGNORE,
};

/*Connection Types (i.e. CCID)*/
enum con_type{
	UNKNOWN,
	CCID2,
	CCID3,
};

/*Half Connection structure*/
struct hcon{
	int					id_len;	/*Length of ID*/
	u_char 				*id;	/*Host ID*/
	__be16				port;	/*Host DCCP port*/
	struct tbl			*table;	/*Host Sequence Number Table*/
	int					size;	/*Size of Sequence Number Table*/
	int					cur;	/*Current TCP Sequence Number*/
	int					high_ack;/*Highest ACK seen*/
	enum con_state		state;	/*Connection state*/
	enum con_type		type;	/*Connection type*/
};

/*Connection structure*/
struct connection{
	struct connection	*next;	/*List pointer*/
	struct hcon			A;		/*Host A*/
	struct hcon			B;		/*Host B*/
};

/*sequence number table structure */
struct tbl{
	__be32 				old;	/*DCCP sequence number */
	u_int32_t			new;	/*TCP sequence number */
	int					size;	/*packet size*/
	enum dccp_pkt_type 	type;	/*packet type*/
};

/*Option flags*/
extern int debug;		/*set to 1 to turn on debugging information*/
extern int yellow;		/*tcptrace yellow line as currently acked packet*/
extern int green;		/*tcptrace green line as currently acked packet*/
extern int sack;		/*add TCP SACKS*/

extern struct connection *chead;/*connection list*/

/*debug printf
 * Levels:
 * 	0) Always print even if debug isn't specified
 *  1) Errors and warnings... Don't overload the screen with too much output
 *  2) Notes and per-packet processing info... as verbose as needed
 */
void dbgprintf(int level, const char *fmt, ...);

/*Function to parse encapsulation*/
int do_encap(int link, struct packet *new, const struct const_packet *old);

/*Connection functions*/
int get_host(u_char *src_id, u_char* dest_id, int id_len, int src_port, int dest_port,
		int pkt_type, struct hcon **fwd, struct hcon **rev);
struct connection *add_connection(u_char *src_id, u_char* dest_id, int id_len,
		int src_port, int dest_port);
int update_state(struct hcon* hst, enum con_state st);
void cleanup_connections();

/*Half Connection/Sequence number functions*/
u_int32_t initialize_hcon(struct hcon *hcn, __be32 initial);
u_int32_t add_new_seq(struct hcon *hcn, __be32 num, int size, enum dccp_pkt_type type);
u_int32_t convert_ack(struct hcon *hcn, __be32 num, struct hcon *o_hcn);
int acked_packet_size(struct hcon *hcn, __be32 num);
unsigned int interp_ack_vect(u_char* hdr);

#endif
