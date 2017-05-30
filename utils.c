#include "utils.h"
#include "marshal.h"

uint8_t broadcast_mac_addr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

void print_mac_addr(uint8_t *mac_addr) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac_addr[i]);
        if (i < 5)
            printf(":");
    }
    printf("\n");
}

void print_ip_addr(uint8_t *ip_addr) {
    for (int i = 0; i < 4; i++) {
        printf("%d", ip_addr[i]);
        if (i < 3)
            printf(".");
    }
    printf("\n");
}

// PROBLEMIC: result byte order? is it correct?
uint16_t cksum(uint8_t *cs_buf, int cs_buf_sz) {
    int i;
    uint32_t sum = 0;
    for (i = 0; i < cs_buf_sz - 1; i += 2) {
        sum += *(uint16_t *)&(cs_buf[i]);
    }
    if (cs_buf_sz & 1) {
    #if __IS_LITTLE_ENDIAN
        sum += cs_buf[i];
    #else
        sum += ((uint16_t)cs_buf[i] << 8);
    #endif
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum;

    // reorder, ?
    // CAUTION: sum is uint32 and hightest 4 bits are ffff, use it directly will cause problem
    uint16_t truncated_sum = (uint16_t)sum;
    uint16_t bytes_reordered_sum = (truncated_sum >> 8) + ((truncated_sum & 0xff) << 8);

    return bytes_reordered_sum;
}

uint16_t segment_checksum(uint8_t protocol, uint8_t *segment, int len,
        uint8_t *src_ip_addr, uint8_t *dst_ip_addr) {
    uint8_t *pseudo_header_buf = malloc(12);
    uint8_t *ptr = pseudo_header_buf;
    memcpy(ptr, src_ip_addr, 4);
    ptr += 4;
    memcpy(ptr, dst_ip_addr, 4);
    ptr += 4;
    ptr = marshal8_mp(0, ptr);
    ptr = marshal8_mp(protocol, ptr);
    ptr = marshal16_mp(len, ptr);

    uint8_t *checksum_buf = realloc(pseudo_header_buf, 12 + len);
    memcpy(checksum_buf + 12, segment, len);
    return cksum(checksum_buf, 12 + len);
}
