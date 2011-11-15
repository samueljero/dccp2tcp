/******************************************************************************
Author: Samuel Jero

Date: 7/2011

Description: Header file for program to convert a DCCP flow to a TCP flow for DCCP
 	 	 analysis via tcptrace.

Notes:
	1)CCID2 ONLY
	2)DCCP MUST use 48 bit sequence numbers
	3)Checksums are not computed (they are zeroed)
	4)Only implements those packet types normally used in a session
	5)DCCP Ack packets show up as TCP packets containing one byte
	6)Very little error checking of packet headers
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


#define MAX_PACKET 	1600	/*Maximum size of TCP packet */
#define	TBL_SZ		40000	/*Size of Sequence Number Table*/




/*Packet structure*/
struct packet{
	struct pcap_pkthdr	*h;		/*libpcap header*/
	u_char				*data;	/*Packet Data*/
	int					length;	/*Packet length*/
	uint32_t			src_id; /*Source ID of packet*/
	uint32_t			dest_id; /*Destination ID of packet*/
};

/*Constant Packet structure*/
struct const_packet{
	const struct pcap_pkthdr *h;	/*libpcap header*/
	const u_char			*data;	/*Packet Data*/
	int						length;	/*Packet length*/
	uint32_t				src_id; /*Source ID of packet*/
	uint32_t				dest_id;/*Destination ID of packet*/
};

/*Connection states*/
enum con_state{
	INIT,
	OPEN,
	CLOSE,
};

/*Host---half of a connection*/
struct host{
	uint32_t 			id;		/*Host ID*/
	__be16				port;	/*Host DCCP port*/
	struct tbl			*table;	/*Host Sequence Number Table*/
	int					size;	/*Size of Sequence Number Table*/
	int					cur;	/*Current TCP Sequence Number*/
	enum con_state		state;	/*Connection state*/
};

/*Connection structure*/
struct connection{
	struct connection	*next;	/*List pointer*/
	struct host			A;		/*Host A*/
	struct host			B;		/*Host B*/
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
int get_host(uint32_t src_id, uint32_t dest_id, int src_port, int dest_port, struct host **fwd, struct host **rev);
struct connection *add_connection(uint32_t src_id, uint32_t dest_id, int src_port, int dest_port);
int update_state(struct host* hst, enum con_state st);

#endif
