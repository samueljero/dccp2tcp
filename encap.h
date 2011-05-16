/******************************************************************************
Author: Samuel Jero

Date: 5/2011

Description: Header file for Encapsulation Functions for DCCP to TCP conversion

******************************************************************************/
#ifndef ENCAP_H_
#define ENCAP_H_

/*
 * All Conversion functions use these standard arguments:
 *  struct pcap_pkthdr *h: This is a copy of the libpcap packet structure.
 * 						   You are free to modify and use the fields.
 *
 *  u_char **nptr:		This is a pointer to a buffer for the new packet.
 * 						Each encapsulation has the responsibility to call
 * 						When a function is called, this will point at the
 * 						location for that protocol's header to start.
 *
 *  int *nlength:		The length of the new packet. Each encapsulation
 *  					can rely on this to contain the remaining buffer
 *  					space AND must return with this parameter containing
 *  					the length of the new packet at that layer.
 *
 *  u_char** optr:		This is a pointer to the buffer containing the
 *  					old packet. When a functio is called, this will
 *  					point at the location of that protocol's header.
 *
 *  int* length:		The length of the old packet. Each encapsulation
 *  					layer MUST decrement this by the amount of it's
 *  					headers. An encapsulation layer MUST never read
 *  					beyond this into optr.
 */

/*
 * Last Level Conversion Function
 * Converts DCCP to TCP for analysis by TCPTRACE
 */
int convert_packet(struct pcap_pkthdr *h, u_char **nptr, int *nlength, const u_char **optr, int *length);

/*Standard Encapsulation Functions*/
int ethernet_encap(struct pcap_pkthdr *h, u_char **nptr, int *nlength, const u_char **optr, int *length);
int linux_cooked_encap(struct pcap_pkthdr *h, u_char **nptr, int *nlength, const u_char **optr, int *length);
int ipv4_encap(struct pcap_pkthdr *h, u_char **nptr, int *nlength, const u_char **optr, int *length);

#endif /* ENCAP_H_ */
