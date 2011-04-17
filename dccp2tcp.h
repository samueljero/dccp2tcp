/******************************************************************************
Author: Samuel Jero

Date: 4/2011

Description: Header file for program to convert a DCCP flow to a TCP flow for DCCP
 	 	 analysis via tcptrace.

Notes:
	1)Supports only a single DCCP connection per capture
	2)Source Port!=Destination Port
	3)DCCP MUST use 48 bit sequence numbers
	4)Checksums are not computed (they are zeroed)
	5)Only implements those packet types normally used in a session
	6)DCCP Ack packets show up as TCP packets containing one byte
	7)Very little error checking of packet headers
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



/*sequence number structure--one per side of the connection */
struct seq_num{
	int cur;			/*current sequence number */
	__be16 addr;		/*connection half id---source port */
	struct tbl *table;	/*sequence number table */
	int size;			/*sequence number table size */
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

/*Half Connection Structures*/
extern struct seq_num	*s1;	/*sequence number structure for side one of connection*/
extern struct seq_num	*s2;	/*sequence number structure for side two of connection*/


/*debug printf
 * Levels:
 * 	0) Always print even if debug isn't specified
 *  1) Errors and warnings... Don't overload the screen with too much output
 *  2) Notes and per-packet processing info... as verbose as needed
 */
void dbgprintf(int level, const char *fmt, ...);

/* Encapsulation functions*/
int eth_ip_encap_pre(struct pcap_pkthdr *h, u_char **nptr, int *nlength, const u_char **optr, int *length);
int eth_ip_encap_post(struct pcap_pkthdr *h, u_char** nptr, int *nlength);

/*The Conversion Function*/
void convert_packet(struct pcap_pkthdr *h, u_char **ndata, int *nlength, const u_char **odata, int *length);

#endif
