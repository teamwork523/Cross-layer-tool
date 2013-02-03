//
////  
//  Copyright (c) 2013 Ashkan Nikravesh. All rights reserved.
//

#include<iostream>
#include<fstream>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <ctime>
#include <sstream>
#include <algorithm>

using namespace std;



int main(int argc, char **argv) {
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE]; 
	string fileaddrstr=string(argv[1]);
	char * fileaddr;
	fileaddr=new char[fileaddrstr.size()+1];
	strcpy (fileaddr, fileaddrstr.c_str());
	handle = pcap_open_offline(fileaddr, errbuf); 
	if (handle == NULL) {
		cerr<<"Couldn't open pcap file :"<<errbuf<<endl;
		exit(1);
	}

	char filter_exp[] = "udp";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct bpf_program fp;
	struct pcap_pkthdr header;
	const u_char *packet;
	net = 0;
	mask = 0;

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		cerr<<"Couldn't parse filter"<<filter_exp<<":"<<pcap_geterr(handle)<<endl;
		exit(0);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		cerr<<"Couldn't install filter "<<filter_exp<<": "<<pcap_geterr(handle)<<endl;
		exit(0);
	}

	while (packet = pcap_next(handle,&header)) {
		u_char *pkt_ptr = (u_char *)packet; 
		time_t timestamp=header.ts.tv_sec;
		cout<<"***"<<endl;
		cout<<"T: "<<timestamp<<endl;
		int caplen=header.caplen;

		for (int i=0;i<caplen;i++){
			short pbyte=(*(pkt_ptr+i)); 
			stringstream sstream;
			sstream << hex << pbyte;
			string result = sstream.str();
			transform(result.begin(), result.end(),result.begin(), ::toupper);
			if (result.length()==1){
				result="0"+result;
			}
			cout<<result<<" ";
		}
		cout<<endl;
	}
	return 0;
}