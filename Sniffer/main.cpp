//
//  main.cpp
//  Sniffer
//
//  Created by Филипп Федяков on 24.11.15.
//  Copyright © 2015 filletofish. All rights reserved.
//

#include <iostream>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#define MAXBYTES2CAPTURE 2048


void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    //[eq
    int i = 0, *counter = (int *)arg;
    printf("Packet count: %d/n", ++(*counter));
    printf("Recieved Packet Size: %d/n", pkthdr -> len);
    printf("Payload: \n");
    
    for(i=0; i<pkthdr->len; i++){
        
        if(isprint(packet[i]))
            printf("%c ", packet[i]);
        else
            printf(". ");
        if((i%16 == 0 && i != 0) || i == pkthdr->len-1)
            printf("\n");
    }
    
    return;
    
}



int main(int argc, const char * argv[]) {
    
    int count = 0;
    
    pcap_t *descr = NULL;
    char *device = NULL, errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    
    /* Filter args */
    const char a[20] = "tcp and dst port 80";
    struct bpf_program filter;
    bpf_u_int32 mask, netaddr = 0;
    
    device = pcap_lookupdev(errbuf);
    printf("Opening device %s/n", device);
    descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf);
    
    pcap_lookupnet(device, &netaddr, &mask, errbuf);
    
    pcap_compile(descr, &filter, a, 1, mask);
    
    pcap_setfilter(descr, &filter);
    
    pcap_loop(descr, -1, processPacket, (u_char *) &count);
    
    
    return 0;
    
}