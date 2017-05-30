#ifndef __UDP_H__
#define __UDP_H__

#include "boar.h"
#include "marshal.h"

#define UDP_HEADER_SIZE 8
struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct proc_out_buf *proc_out_udp(struct udp_socket *udp_socket);

uint8_t *marshal_udp_header(struct udp_header *udp_header);
/*! caution: udp_header struct is modified */
uint8_t *marshal_udp_header2(struct udp_header *udp_header);
struct udp_header *unmarshal_udp_header(uint8_t *ptr);
void print_udp_header(struct udp_header *udp_header);

#endif
