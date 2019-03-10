#ifndef FUNCTION_H
#define FUNCTION_H
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#define DEST_MAC_BYTE 6
#define SOURCE_MAC_BYTE 6
#define TYPE_BYTE 2

#define IPv4 0x0800
#define ARP 0x0806

#define E_HEADER_BYTE 14
#define E_ARP_BYTE 28

#define NUM_ARG 2

#define REQUEST_CODE 0x0001
#define REPLY_CODE 0x0002

#define IP_VERS_BIT_MASK 0xF0
#define IP_VERS_SHIFT_BIT 4
#define HEADER_LEN_BIT_MASK 0x0F
#define FOUR 4
#define DIFF_SERV_BIT_MASK 0xFC
#define ECN_BIT_MASK 0x03
#define DIFF_SHIFT_BIT 2

#define ICMP_PROTOCOL 0x01
#define TCP_PROTOCOL 0x06
#define UDP_PROTOCOL 0x11

#define REQUEST 0x08
#define REPLY 0x00

#define HTTP 80
#define TELNET 23
#define FTP 21
#define POP3 110
#define SMTP 25
#define DNS 53
#define NBNS 0x0089

#define OPTION_NUM_BYTE 8
#define HEADER_LENGTH_SHIFT 12
#define SYN 0x0002
#define RST 0x0004
#define FIN 0x0001
#define ACK 0x0010

#define DATA_SIZE 256
struct ethernet_header{
    struct ether_addr dest_MAC;
    struct ether_addr source_MAC;
    uint16_t type;
}__attribute__((packed));

struct arp_header{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    struct ether_addr sender_MAC_addr;
    struct in_addr sender_IP_addr; //4 bytes
    struct ether_addr target_MAC_addr;
    struct in_addr target_IP_addr; //4 bytes
}__attribute__((packed));

struct ipv4_header{
    uint8_t vers;
    uint8_t diff_ser;
    uint16_t total_len;
    uint16_t ident;
    uint16_t flags;
    uint8_t live_time;
    uint8_t protocol;
    uint16_t header_chcksum;
    struct in_addr source;
    struct in_addr dest;
}__attribute__((packed));

struct icmp_header{
    uint8_t type;
    uint8_t code;
    uint16_t ck_sum;
    uint16_t ident;
    uint16_t sequence_num;
}__attribute__((packed));

struct udp_header{
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t chcksum;
}__attribute__((packed));

struct tcp_header{
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t sequence_num;
    uint32_t ack_num;
    uint16_t flags;
    uint16_t win_size_val;
    uint16_t chck_sum;
    uint16_t ur_prt;
    //uint8_t options[OPTION_NUM_BYTE];
    uint8_t data[65535];
}__attribute__((packed));

struct pseudo_header{
    uint32_t source_addr;
    uint32_t dest_addr;
    uint8_t zeros;
    uint8_t protocol;
    uint16_t tcp_length;
    struct tcp_header tcp_header;
}__attribute__((packed));

void print_ether_header(u_char *e_header_ptr);
void print_IPv4_header(u_char *ipv4_header_ptr);
void print_ARP_header(u_char *arp_header_ptr);
void print_ICMP_header(u_char *icmp_header_ptr);
void print_UDP_header(u_char *udp_header_ptr);
void print_TCP_header(u_char *tcp_header_ptr, u_char *ip_header_ptr);
#endif
