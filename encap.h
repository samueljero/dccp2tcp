/******************************************************************************
Author: Samuel Jero

Date: 11/2011

Description: Header file for Encapsulation Functions for DCCP to TCP conversion

******************************************************************************/
#ifndef ENCAP_H_
#define ENCAP_H_

/*
 * All Conversion functions use these standard arguments:
 * struct packet *new:		The New packet. It contains the following fields.
 *
 *  	struct pcap_pkthdr *h: This is a copy of the libpcap packet structure.
 * 							   You are free to modify and use the fields.
 *
 *  	u_char *data:		This is a pointer to a buffer for the new packet.
 * 							Each encapsulation has the responsibility to call
 * 							When a function is called, this will point at the
 * 							location for that protocol's header to start.
 *
 *  	int length:			The length of the new packet. Each encapsulation
 *  						can rely on this to contain the remaining buffer
 *  						space AND must return with this parameter containing
 *  						the length of the new packet at that layer.
 *
 *  	uint32_t src_id:	This is an ID for the source host. If you are going to
 *  						demultiplex DCCP on anything but Port Numbers, you
 *  						need to set this field. Typically this would be an
 *  						IP address.
 *
 *  	uint32_t dest_id: 	This is an ID for the destination host. If you are going to
 *  						demultiplex DCCP on anything but Port Numbers, you
 *  						need to set this field. Typically this would be an
 *  						IP address.
 *
 *	struct const_packet *old:	The Old packet. It contains the following fields.
 *
 *  	u_char* data:		This is a pointer to the buffer containing the
 *  						old packet. When a function is called, this will
 *  						point at the location of that protocol's header.
 *
 *  	int length:			The length of the old packet. Each encapsulation
 *  						layer MUST decrement this by the amount of it's
 *  						headers. An encapsulation layer MUST never read
 *  						beyond this into old->data.
 */

/*
 * Last Level Conversion Function
 * Converts DCCP to TCP for analysis by TCPTRACE
 */
int convert_packet(struct packet *new, const struct const_packet *old);

/*Standard Encapsulation Functions*/
int ethernet_encap(struct packet *new, const struct const_packet *old);
int linux_cooked_encap(struct packet *new, const struct const_packet *old);
int ipv4_encap(struct packet *new, const struct const_packet *old);

#endif /* ENCAP_H_ */
