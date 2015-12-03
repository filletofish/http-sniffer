//  HTTP SNIFFER

//  main.cpp
//  Sniffer
//
//  Copyright © 2015 filletofish. All rights reserved.
//

//  Description:
//  Printing IP SRC and IP DST of all packets
//  if content-type is urlencoded, than all http payload is printed

#include <iostream>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <vector>
#include <sstream>


#define MAXBYTES2CAPTURE 2048

using namespace std;

// global vars
int content_length = 0;
bool content_to_get = false;
string global_buff = "";
tcp_seq ack;


vector<string> &split(const string &s, char delim, vector<string> &elems) {
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}


vector<string> split(const string &s, char delim) {
    vector<string> elems;
    split(s, delim, elems);
    return elems;
}


void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    string local_buff = "";
    
    int *ethernet_bytes_count = (int *)arg; // size of ethernet header
    
    // getting IP header
    struct ip *iphdr = (struct ip*) (packet + *ethernet_bytes_count);
    // getting TCP header
    struct tcphdr *tcphdr = (struct tcphdr*) (packet + *ethernet_bytes_count + 4* iphdr->ip_hl);
    
    int headers_length = *ethernet_bytes_count +  4* iphdr->ip_hl + 4*tcphdr->th_off;
    // the rest is payload and cheksum
    string payload = string(reinterpret_cast<const char*>(packet + headers_length));
    
    // payload is not empty
    if (pkthdr->len - headers_length > 0) {
        
        // if previous packet had content-type urlencoded
        if (content_to_get && content_length > 0 && tcphdr->th_ack == ack) {
            local_buff = global_buff;
            vector <string> keys_values = split(payload.c_str(), '&');
            for (vector<string>::iterator it = keys_values.begin(); it != keys_values.end(); ++it)
                local_buff += *it + "\n";
            
            global_buff = "";
            content_to_get = false;
            content_length = 0;
        }
        
        // usual packet
        else {
            local_buff += "\n ...\n\nPacket starts: \n" ;
            local_buff += "IP DEST: " + (string)inet_ntoa(iphdr->ip_dst) + "\n";
            local_buff += "IP SRC: "  + (string)inet_ntoa(iphdr->ip_src) + "\n";
            local_buff += "Payload: \n";
            
            if (payload.find("Content-Type:") == string::npos)
                local_buff += "Packet has no Content-Type.\n";
            
            else {
                // parsing content-type
                int a = (int) payload.find("Content-Type:");
                int b = (int) payload.find("\n", a);
                a += ((string)"Content-Type:").length();
                
                local_buff += "Content-Type:"  + payload.substr(a, b-a) + "\n";
                
                // For urlencoded we get content length
                
                if (payload.find("application/x-www-form-urlencoded") != string::npos) {
                    a = (int) payload.find("Content-Length:");
                    b = (int) payload.find("\n", a);
                    a += ((string)"Content-Length:").length();
                    
                    ack = tcphdr->th_ack;
                    content_length = atoi(payload.substr(a, b-a).c_str());
                    global_buff = local_buff;
                    content_to_get = true;
                }
            
            }
            
        }
        
        local_buff += "Packet end. \n";
        printf("%s", local_buff.c_str());
    }
    
    return;
    
}


int main(int argc, const char * argv[]) {
    
    int ethernet_bytes_count = 0;
    
    pcap_t *descr = NULL;
    char *device = NULL, errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    
    // Filter args
    const char a[20] = "tcp and dst port 80";
    struct bpf_program filter;
    bpf_u_int32 mask, netaddr = 0;
    
    device = pcap_lookupdev(errbuf);
    printf("Opening device %s/n", device);
    descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf);
    
    pcap_lookupnet(device, &netaddr, &mask, errbuf);
    
    pcap_compile(descr, &filter, a, 1, mask);
    
    pcap_setfilter(descr, &filter);
    
    printf("\nSniffing started! \n\n");
    
    // getting ethernet header link
    int datalink = pcap_datalink(descr);
    if (datalink == DLT_EN10MB) {
        ethernet_bytes_count = 14;
    }
    else if (datalink == DLT_IEEE802_11) {
        ethernet_bytes_count = 22;
    }
    
    
    /* Context */
    u_char *context = (u_char*) &ethernet_bytes_count;
    // main loop of sniffing
    pcap_loop(descr, -1, processPacket, (u_char *) context);
    
    return 0;
    
}

/*
 for (i = 0; i < pkthdr->len - (*ethernet_bytes_count + 4*tcphdr->th_off + 4* iphdr->ip_hl) ; i++) {
 if(isprint(payload[i]))
 printf("%c", payload[i]);
 else
 printf(" . ");
 if((i%16 == 0 && i != 0) || i == pkthdr->len-1)
 printf("\n");
 } */



//printf("Recieved Packet Size: %d/n", pkthdr -> len);
//printf("Payload: \n");

/*for(i=0; i<pkthdr->len; i++){
 
 if(isprint(packet[i]))
 printf("%c", packet[i]);
 else
 printf("");
 if((i%16 == 0 && i != 0) || i == pkthdr->len-1)
 printf("\n");
 } */