#ifndef __UTILS_H__
#define __UTILS_H__

#include "boar.h"

void print_mac_addr(uint8_t *mac_addr);
void print_ip_addr(uint8_t *ip_addr);
uint16_t cksum(uint8_t *cs_buf, int cs_buf_sz);
uint16_t segment_checksum(uint8_t protocol, uint8_t *segment, int len,
    uint8_t *src_ip_addr, uint8_t *dst_ip_addr);

#endif
