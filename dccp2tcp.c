/******************************************************************************
Utility to convert a DCCP flow to a TCP flow for DCCP analysis via
		tcptrace.

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
	3)DCCP DATA packets are not implemented (Linux doesn't use them)
	4)DCCP Ack packets show up as TCP packets containing one byte
******************************************************************************/
#include "dccp2tcp.h"


#define DCCP2TCP_VERSION 1.6
#define COPYRIGHT_YEAR 2013


int debug=0;	/*set to 1 to turn on debugging information*/
int yellow=0;	/*tcptrace yellow line as currently acked packet*/
int green=0;	/*tcptrace green line as currently acked packet*/
int sack=0;		/*add TCP SACKS*/


pcap_t*			in;			/*libpcap input file discriptor*/
pcap_dumper_t	*out;		/*libpcap output file discriptor*/
struct connection *chead;	/*connection list*/


void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void version();
void usage();


/*Parse commandline options and open files*/
int main(int argc, char *argv[])
{
	char ebuf[200];
	char *erbuffer=ebuf;
	char *dfile=NULL;
	char *tfile=NULL;

	/*parse commandline options*/
	if(argc > 9){
		usage();
	}

	/*loop through commandline options*/
	for(int i=1; i < argc; i++){
		if(argv[i][0]!='-' || (argv[i][0]=='-' && strlen(argv[i])==1)){
			if(dfile==NULL  || argv[i][0]=='-'){
				/*assign first non-dash (or only dash) argument to the dccp file*/
				dfile=argv[i];
			}else{
				if(tfile==NULL){
					tfile=argv[i]; /*assign second non-dash argument to the dccp file*/
				}else{
					usage();
				}
			}
		}else{
			if(argv[i][1]=='d' && strlen(argv[i])==2){ /* -d */
				debug++;
			}
			if(argv[i][1]=='y' && strlen(argv[i])==2){ /* -y */
				yellow=1;
			}
			if(argv[i][1]=='g' && strlen(argv[i])==2){ /* -g */
				green=1;
			}
			if(argv[i][1]=='s' && strlen(argv[i])==2){ /* -s */
				sack++;
			}
			if(argv[i][1]=='h' && strlen(argv[i])==2){ /* -h */
				usage();
			}
			if(argv[i][1]=='V' && strlen(argv[i])==2){ /* -V */
				version();
			}
		}
	}
	
	if(dfile==NULL || tfile==NULL){
		usage();
	}

	/*all options validated*/

	if(debug){
		dbgprintf(1,"Debug On\n");
		if(green){
			dbgprintf(1,"Tcptrace green line at highest acknowledgment\n");
		}else{
			dbgprintf(1,"Tcptrace green line at highest acknowledged acknowledgment\n");
		}
		if(yellow){
			dbgprintf(1,"Tcptrace yellow line at highest acknowledgment\n");
		}else{
			dbgprintf(1,"Tcptrace yellow line window value (a made up number)\n");
		}
		if(sack){
			dbgprintf(1,"Adding TCP SACKS\n");
		}
		dbgprintf(1,"Input file: %s\n", dfile);
		dbgprintf(1,"Output file: %s\n", tfile);
	}

	/*attempt to open input file*/
	in=pcap_open_offline(dfile, erbuffer);
	if(in==NULL){
		dbgprintf(0,"Error opening input file\n");
		exit(1);
	}

	/*attempt to open output file*/
	out=pcap_dump_open(in,tfile);
	if(out==NULL){
		dbgprintf(0,"Error opening output file\n");
		exit(1);
	}

	/*process packets*/
	chead=NULL;
	u_char *user=(u_char*)out;
	pcap_loop(in, -1, handle_packet, user);	
	
	/*close files*/
	pcap_close(in);
	pcap_dump_close(out);

	/*Delete all connections*/
	cleanup_connections();
return 0;
}


/*call back function for pcap_loop--do basic packet handling*/
void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	u_char 				*ndata;
	struct pcap_pkthdr 	nh;
	int					link_type;
	struct packet		new;
	struct const_packet	old;

	/*Determine the link type for this packet*/
	link_type=pcap_datalink(in);

	/*create new libpcap header*/
	memcpy(&nh, h, sizeof(struct pcap_pkthdr));

	/*Setup packet structs*/
	old.h=h;
	old.length=h->caplen;
	old.data=bytes;
	old.dest_id=NULL;
	old.src_id=NULL;
	new.h=&nh;
	new.length=MAX_PACKET;
	new.dest_id=NULL;
	new.src_id=NULL;

	/*create buffer for new packet*/
	new.data=ndata=malloc(MAX_PACKET);
	if(ndata==NULL){
		dbgprintf(0,"Error: Couldn't allocate Memory\n");
		exit(1);
	}

	/*make sure the packet is all zero*/
	memset(new.data, 0, MAX_PACKET);
	
	/*do all the fancy conversions*/
	if(!do_encap(link_type, &new, &old)){
		free(ndata);
		return;
	}

	/*save packet*/
	pcap_dump(user,&nh, ndata);

	free(ndata);
return;
}

/*do all the dccp to tcp conversions*/
int convert_packet(struct packet *new, const struct const_packet* old)
{
	struct tcphdr 				*tcph;
	struct dccp_hdr 			*dccph;
	struct dccp_hdr_ext 		*dccphex;
	struct host					*h1=NULL;
	struct host					*h2=NULL;

	/*Safety checks*/
	if(!new || !old || !new->data || !old->data || !new->h || !old->h){
		dbgprintf(0,"Error:  Convert Packet Function given bad data!\n");
		exit(1);
		return 0;
	}
	if(old->length < (sizeof(struct dccp_hdr) + sizeof(struct dccp_hdr_ext)) || new->length < sizeof(struct dccp_hdr)){
		dbgprintf(0, "Error: DCCP Packet Too short!\n");
		return 0;
	}

	/*cast header pointers*/
	tcph=(struct tcphdr*)new->data;
	dccph=(struct dccp_hdr*)old->data;
	dccphex=(struct dccp_hdr_ext*)(old->data+sizeof(struct dccp_hdr));

	dbgprintf(2,"Sequence Number: %llu\n", (unsigned long long)
			(((unsigned long)ntohs(dccph->dccph_seq)<<32) + ntohl(dccphex->dccph_seq_low)));

	/*Ensure packet is at least as large as DCCP header*/
	if(old->length < dccph->dccph_doff*4){
		dbgprintf(0, "Error: DCCP Header truncated\n");
		return 0;
	}

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

	/*TODO: Add CCID detection*/
	if(h1->type==CCID2 && h2->type==CCID2){
		if(ccid2_convert_packet(new,old)==0){
			return 0;
		}
	}
	if(h1->type==CCID3 && h2->type==CCID3){
		//ccid3_convert_packet(new,old);
	}
	if(ccid2_convert_packet(new,old)==0){
		return 0;
	}

	/*Compute TCP checksums*/
	if(new->id_len==IP4_ADDR_LEN){
			tcph->check=0;
			tcph->check=ipv4_pseudohdr_chksum(new->data,
					new->length, new->dest_id, new->src_id, 6);
	}else if(new->id_len==IP6_ADDR_LEN){
			tcph->check=0;
			tcph->check=ipv6_pseudohdr_chksum(new->data,
					new->length, new->dest_id, new->src_id, 6);
	}else{
		tcph->check=0;
		dbgprintf(2,"Unknown ID Length, can't do checksums");
	}

	return 1;
}

void version(){
	dbgprintf(0, "dccp2tcp version %.1f\nCopyright (C) %i Samuel Jero <sj323707@ohio.edu>\n", DCCP2TCP_VERSION,COPYRIGHT_YEAR);
	dbgprintf(0, "This program comes with ABSOLUTELY NO WARRANTY.\n");
	dbgprintf(0, "This is free software, and you are welcome to\nredistribute it under certain conditions.\n");
	exit(0);
}

/*Usage information for program*/
void usage()
{
	dbgprintf(0,"Usage: dccp2tcp dccp_file tcp_file [-d] [-h] [-V] [-y] [-g] [-s]\n");
	dbgprintf(0, "          -d   Debug. May be repeated for aditional verbosity.\n");
	dbgprintf(0, "          -V   Version information\n");
	dbgprintf(0, "          -h   Help\n");
	dbgprintf(0, "          -y   Yellow line is highest ACK\n");
	dbgprintf(0, "          -g   Green line is highest ACK\n");
	dbgprintf(0, "          -s   convert ACK Vectors to SACKS\n");
	exit(0);
}

/*Debug Printf*/
void dbgprintf(int level, const char *fmt, ...)
{
    va_list args;
    if(debug>=level){
    	va_start(args, fmt);
    	vfprintf(stderr, fmt, args);
    	va_end(args);
    }
}
