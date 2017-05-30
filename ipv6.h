#ifndef __IPV6_H__
#define __IPV6_H__

#include "boar.h"

#define IPV6_HEADER_SIZE 40
struct ipv6_header {
    uint8_t version: 4;
    uint32_t flags: 28;
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t source[16];
    uint8_t destination[16];
};

#endif
