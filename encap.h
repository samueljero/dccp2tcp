/******************************************************************************
Utility to convert a DCCP flow to a TCP flow for DCCP analysis via
		tcptrace. Header file for Encapsulation Functions for DCCP to TCP conversion.

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
 *  	int id_len:			Length of the source and destination ID.
 *
 *  	u_char *src_id:		This is an ID for the source host. If you are going to
 *  						demultiplex DCCP on anything but Port Numbers, you
 *  						need to set this field. Typically this would be an
 *  						IP address.
 *
 *  	u_char *dest_id: 	This is an ID for the destination host. If you are going to
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
int ipv6_encap(struct packet *new, const struct const_packet *old);

#endif /* ENCAP_H_ */
