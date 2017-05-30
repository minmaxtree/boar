#ifndef __IP_H__
#define __IP_H__
#include "boar.h"
#include "stack.h"
#include "ethernet.h"

#define IP_HEADER_SIZE 20  // size excluding options
struct ip_header {
    uint8_t version: 4;
    uint8_t header_length: 4;
    uint8_t differentiated_services;
    uint16_t total_len;
    uint16_t id;
    // uint8_t flags;
    uint8_t dont_fragment: 1;
    uint8_t more_fragments: 1;
    uint16_t fragment_offset: 13;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t source[4];
    uint8_t destination[4];
};

struct proc_out_buf *proc_out_ip(uint8_t *l_ip_addr, uint8_t *r_ip_addr,
        uint8_t *l_mac_addr, uint8_t *r_mac_addr,
        uint8_t proto, uint8_t *seg, uint16_t seg_len);

int ip_addr_eq(uint8_t *ip_addr1, uint8_t *ip_addr2);
uint8_t *marshal_ip_header(struct ip_header *ip_header);
uint8_t *marshal_ip_header2(struct ip_header *ip_header);
struct ip_header *unmarshal_ip_header(uint8_t *ptr);
void print_ip_header(struct ip_header *ip_header);

#endif
