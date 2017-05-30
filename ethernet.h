#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#include "boar.h"
#include "stack.h"

#define ETHERNET_HEADER_SIZE 14
struct ethernet_header {
    uint8_t dst_addr[6];
    uint8_t src_addr[6];
    uint16_t type;
};

struct proc_out_buf *proc_out_ethernet(uint8_t *dst_addr, uint8_t *src_addr,
    uint16_t type, uint8_t *packet, uint16_t packet_len);

uint8_t *marshal_ethernet_header(struct ethernet_header *ethernet_header);
struct ethernet_header *unmarshal_ethernet_header(uint8_t *ptr);
void print_ethernet_header(struct ethernet_header *ethernet_header);

#endif
