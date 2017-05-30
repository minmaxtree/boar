#ifndef __ICMP_H__
#define __ICMP_H__
#include "boar.h"

#define ICMP_HEADER_SIZE 16
struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq_num;
    uint8_t timestamp[8];
};

enum icmp_type {
    ICMP_ECHO_REPLY = 0,
    ICMP_ECHO_REQUEST = 8,
};

uint8_t *marshal_icmp_header(struct icmp_header *icmp_header);
struct icmp_header *unmarshal_icmp_header(uint8_t *ptr);
void print_icmp_header(struct icmp_header *icmp_header);

#endif
