#include "checksum.h"
#include "function.h"

void print_IPv4_header(u_char *ipv4_header_ptr){
    uint8_t ver = 0, len = 0, diff_serv_bit = 0, ecn_bit = 0, protocol = 0;
    struct ipv4_header ipv4_header;

    memcpy(&ipv4_header, ipv4_header_ptr, sizeof(struct ipv4_header));
    ver = ipv4_header.vers;
    len = ipv4_header.vers;
    diff_serv_bit = ipv4_header.diff_ser;
    ecn_bit = ipv4_header.diff_ser;
    protocol = 0;

    ver &= IP_VERS_BIT_MASK;
    ver >>= IP_VERS_SHIFT_BIT;
    len &= HEADER_LEN_BIT_MASK;
    len *= FOUR;

    diff_serv_bit &= DIFF_SERV_BIT_MASK;
    ecn_bit &= ECN_BIT_MASK;
    diff_serv_bit >>= DIFF_SHIFT_BIT;

    printf("\tIP Header\n");
    printf("\t\tIP Version: %d\n", ver);
    printf("\t\tHeader Len (bytes): %d\n", len);
    printf("\t\tTOS subfields:\n");
    printf("\t\t   Diffserv bits: %d\n", diff_serv_bit);
    printf("\t\t   ECN bits: %d\n", ecn_bit);
    printf("\t\tTTL: %d\n", ipv4_header.live_time);
    printf("\t\tProtocol: ");

    switch(protocol = ipv4_header.protocol){
        case(ICMP_PROTOCOL):
            printf("ICMP\n");
            break;
        case(TCP_PROTOCOL):
            printf("TCP\n");
            break;
        case(UDP_PROTOCOL):
            printf("UDP\n");
            break;
        default:
            printf("Unknown\n");
    }

    printf("\t\tChecksum: ");
    if(!in_cksum((unsigned short *)ipv4_header_ptr, len)){
        printf("Correct (0x%04x)\n", ntohs(ipv4_header.header_chcksum));
    }
    else{
        printf("Incorrect (0x%04x)\n", ntohs(ipv4_header.header_chcksum));
    }

    printf("\t\tSender IP: %s\n", inet_ntoa(ipv4_header.source));
    printf("\t\tDest IP: %s\n", inet_ntoa(ipv4_header.dest)); 
    printf("\n");
    switch(protocol){
        case(ICMP_PROTOCOL):
            print_ICMP_header(ipv4_header_ptr + len);
            break;
        case(TCP_PROTOCOL):
            print_TCP_header(ipv4_header_ptr + sizeof(struct ipv4_header),
                             ipv4_header_ptr);
            break;
        case(UDP_PROTOCOL):
            print_UDP_header(ipv4_header_ptr + sizeof(struct ipv4_header));
            break;
        default:
            ;
    }
}

void print_UDP_header(u_char *udp_header_ptr){ 
    struct udp_header udp_header;
    uint16_t port = 0;
    memcpy(&udp_header, udp_header_ptr, sizeof(struct udp_header));
    printf("\tUDP Header\n");
    printf("\t\tSource Port:  ");
    switch(port = ntohs(udp_header.source_port)){
        case(DNS):
            printf("DNS\n");
            break;
        case(HTTP):
            printf("HTTP\n");
            break;
        case(TELNET):
            printf("TELNET\n");
            break;
        case(FTP):
            printf("FTP\n");
            break;
        case(POP3):
            printf("POP3\n");
            break;
        case(SMTP):
            printf("SMTP\n");
            break;
        default:
            printf("%d\n", port);
    }
    printf("\t\tDest Port:  "); 
    switch(port = ntohs(udp_header.dest_port)){
        case(DNS):
            printf("DNS\n");
            break;
        case(HTTP):
            printf("HTTP\n");
            break;
        case(TELNET):
            printf("TELNET\n");
            break;
        case(FTP):
            printf("FTP\n");
            break;
        case(POP3):
            printf("POP3\n");
            break;
        case(SMTP):
            printf("SMTP\n");
            break;
        default:
            printf("%d\n", port);
    }
}

void print_ICMP_header(u_char *icmp_header_ptr){
    struct icmp_header icmp_header;
    memcpy(&icmp_header, icmp_header_ptr, sizeof(struct icmp_header));
    printf("\tICMP Header\n");
    if(icmp_header.type == REQUEST)
        printf("\t\tType: Request\n");
    else if(icmp_header.type == REPLY)
        printf("\t\tType: Reply\n");
    else
        printf("\t\tType: %d\n", icmp_header.type);
}

void print_ARP_header(u_char *arp_header_ptr){
    uint32_t opcode_val = 0;
    struct arp_header arp_header;
    memcpy(&arp_header, arp_header_ptr, sizeof(struct arp_header));
    printf("\tARP header\n");
    printf("\t\tOpcode: ");
    switch(opcode_val = ntohs(arp_header.opcode)){
        case(REQUEST_CODE):
            printf("Request\n");
            break;
        case(REPLY_CODE):
            printf("Reply\n");
            break;
        default:
            printf("%d\n", opcode_val); 
    }
    printf("\t\tSender MAC: %s\n", 
            ether_ntoa(&(arp_header.sender_MAC_addr)));
    printf("\t\tSender IP: %s\n",
            inet_ntoa(arp_header.sender_IP_addr));
    printf("\t\tTarget MAC: %s\n",
            ether_ntoa(&(arp_header.target_MAC_addr)));
    printf("\t\tTarget IP: %s\n",
            inet_ntoa(arp_header.target_IP_addr));
    printf("\n");
}

void print_TCP_header(u_char *tcp_header_ptr, u_char *ip_header_ptr){
    struct tcp_header tcp_header;
    struct pseudo_header pseudo_head;
    struct ipv4_header ip_header;
    uint8_t ip_header_len;
    uint16_t len_flags;
    uint16_t port = 0;
    uint16_t cksum = 0;

    memcpy(&tcp_header, tcp_header_ptr, sizeof(struct tcp_header));
    len_flags = ntohs(tcp_header.flags);
    len_flags >>= HEADER_LENGTH_SHIFT;
    printf("\tTCP Header\n");
    printf("\t\tSource Port:  ");

    switch(port = ntohs(tcp_header.source_port)){
        case(HTTP):
            printf("HTTP\n");
            break;
        case(TELNET):
            printf("TELNET\n");
            break;
        case(FTP):
            printf("FTP\n");
            break;
        case(POP3):
            printf("POP3\n");
            break;
        case(SMTP):
            printf("SMTP\n");
            break;
        default:
            printf("%d\n", port);
    }
    printf("\t\tDest Port:  ");
    switch(port = ntohs(tcp_header.dest_port)){
        case(HTTP):
            printf("HTTP\n");
            break;
        case(TELNET):
            printf("TELNET\n");
            break;
        case(FTP):
            printf("FTP\n");
            break;
        case(POP3):
            printf("POP3\n");
            break;
        case(SMTP):
            printf("SMTP\n");
            break;
        default:
            printf("%d\n", port);
    }
    printf("\t\tSequence Number: %u\n", ntohl(tcp_header.sequence_num));
    printf("\t\tACK Number: %u\n", ntohl(tcp_header.ack_num));
    printf("\t\tData Offset (bytes): %d\n", len_flags*FOUR);

    printf("\t\tSYN Flag: ");
    len_flags = ntohs(tcp_header.flags);
    (len_flags & SYN) ? printf("Yes\n") : printf("No\n");
    printf("\t\tRST Flag: ");
    (len_flags & RST) ? printf("Yes\n") : printf("No\n");
    printf("\t\tFIN Flag: ");
    (len_flags & FIN) ? printf("Yes\n") : printf("No\n");
    printf("\t\tACK Flag: ");
    (len_flags & ACK) ? printf("Yes\n") : printf("No\n");

    printf("\t\tWindow Size: %d\n", ntohs(tcp_header.win_size_val));
    printf("\t\tChecksum: ");

    memcpy(&ip_header, ip_header_ptr, sizeof(struct ipv4_header));
    memcpy(&pseudo_head.source_addr, &ip_header.source, 
        sizeof(struct in_addr));
    memcpy(&pseudo_head.dest_addr, &ip_header.dest, 
        sizeof(struct in_addr));
    pseudo_head.zeros = 0x00;
    memcpy(&pseudo_head.protocol, &ip_header.protocol, sizeof(uint8_t));
   
    ip_header_len = ip_header.vers;
    ip_header_len &= HEADER_LEN_BIT_MASK;
    pseudo_head.tcp_length = 
        htons(ntohs(ip_header.total_len) - ip_header_len*FOUR);

    memcpy(&pseudo_head.tcp_header, &tcp_header, sizeof(struct tcp_header));
    if(!(cksum = in_cksum((unsigned short *)&pseudo_head, 
            ntohs(pseudo_head.tcp_length)+12))){
        printf("Correct (0x%04x)\n", ntohs(pseudo_head.tcp_header.chck_sum));
    }
    else{
        printf("Incorrect (0x%04x)\n", ntohs(pseudo_head.tcp_header.chck_sum));
    }
}

void print_ether_header(u_char *e_header_ptr){
    uint32_t opcode_val = 0;
    struct ethernet_header ethernet_header;
    memcpy(&ethernet_header, e_header_ptr, sizeof(struct ethernet_header));
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %s\n", 
            ether_ntoa(&(ethernet_header.dest_MAC)));
    printf("\t\tSource MAC: %s\n", 
            ether_ntoa(&(ethernet_header.source_MAC)));
    printf("\t\tType: ");
    switch(opcode_val = ntohs(ethernet_header.type)){
        case(IPv4):
            printf("IP\n\n");
            print_IPv4_header(e_header_ptr + sizeof(struct ethernet_header));
            break;
        case(ARP):
            printf("ARP\n\n");
            print_ARP_header(e_header_ptr + sizeof(struct ethernet_header));
            break;
        default:
            printf("%d\n", opcode_val); 
    }
}


