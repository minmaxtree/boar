#ifndef __ARP_H__
#define __ARP_H__

#include "boar.h"

#define ARP_HEADER_SIZE 28
struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac_addr[6];
    uint8_t sender_ip_addr[4];
    uint8_t target_mac_addr[6];
    uint8_t target_ip_addr[4];
};

enum arp_opcode {
    ARP_REQUEST = 1,
    ARP_REPLY = 2,
};

struct proc_out_buf *proc_out_arp(uint8_t *sender_mac_addr, uint8_t *target_mac_addr,
        uint8_t *sender_ip_addr, uint8_t *target_ip_addr, uint8_t *r_mac_addr, uint16_t opcode);

void print_arp_header(struct arp_header *arp_header);
uint8_t *marshal_arp_header(struct arp_header *arp_header);
struct arp_header *unmarshal_arp_header(uint8_t *ptr);

#endif
