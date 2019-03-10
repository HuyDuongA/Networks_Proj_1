#include "function.h"

char errbuf[PCAP_ERRBUF_SIZE];

int main(int argc, const char *argv[]){
    pcap_t *p = NULL;
    int packet_num = 0;
    int packet_len = 0;
    struct pcap_pkthdr *pckt_struct = NULL;
    u_char *header_ptr = NULL;
    //Initialize ethernet struct to 0 values.
    //struct ethernet_header ethernet_header;
    //struct ipv4_header ipv4_header;
    //struct arp_header arp_header;

    if(argc != NUM_ARG){
        perror("Invalid number of argument");
        exit(EXIT_FAILURE);
    }
    else{
        if(!(p = pcap_open_offline(argv[1], errbuf))){
            perror(argv[1]);
            exit(EXIT_FAILURE);
        }   
        
        
        //Capture packets
        while(pcap_next_ex(p, &pckt_struct, (const u_char **)&header_ptr) > 0){
            
            packet_num++;
            packet_len = pckt_struct->len;
            //Print packet info and ethernet header
            printf("\nPacket number: %d  Packet Len: %d\n\n",
                    packet_num, packet_len);
            print_ether_header(header_ptr);
            
        }
    }
    return 0;
}
