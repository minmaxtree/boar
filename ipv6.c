#include "ipv6.h"
#include "marshal.h"

uint8_t *marshal_ipv6_header(struct ipv6_header *ipv6_header) {
    uint8_t *buf = malloc(IPV6_HEADER_SIZE);
    uint8_t *ptr = buf;
    uint32_t vf = (ipv6_header->version << 28) + ipv6_header->flags;
    ptr = marshal32_mp(vf, ptr);
    ptr = marshal16_mp(ipv6_header->payload_len, ptr);
    ptr = marshal8_mp(ipv6_header->next_header, ptr);
    ptr = marshal8_mp(ipv6_header->hop_limit, ptr);
    memcpy(ptr, ipv6_header->source, 16);
    ptr += 16;
    memcpy(ptr, ipv6_header->destination, 16);
    ptr += 16;

    return buf;
}

struct ipv6_header *unmarshal_ipv6_header(uint8_t *ptr) {
    struct ipv6_header *ipv6_header = malloc(sizeof(*ipv6_header));
    uint32_t vf = unmarshal32_mp(&ptr);
    ipv6_header->version = vf >> 28;
    ipv6_header->flags = vf & 0xfffffff;
    ipv6_header->payload_len = unmarshal16_mp(&ptr);
    ipv6_header->next_header = unmarshal8_mp(&ptr);
    ipv6_header->hop_limit = unmarshal8_mp(&ptr);
    memcpy(ipv6_header->source, ptr, 16);
    ptr += 16;
    memcpy(ipv6_header->destination, ptr, 16);
    ptr += 16;

    return ipv6_header;
}

void print_ipv6_addr(uint8_t *ipv6_addr) {
    for (int i = 0; i < 16; i++) {
        printf("%02x", ipv6_addr[i]);
        if (i != 15)
            printf(":");
    }
    puts("");
}

void print_ipv6_header(struct ipv6_header *ipv6_header) {
    printf("    version: %u\n", ipv6_header->version);
    printf("    flags: %u\n", ipv6_header->flags);
    printf("    payload_len: %u\n", ipv6_header->payload_len);
    printf("    next_header: %u\n", ipv6_header->next_header);
    printf("    hop_limit: %u\n", ipv6_header->hop_limit);
    printf("    source: "); print_ipv6_addr(ipv6_header->source);
    printf("    destination: "); print_ipv6_addr(ipv6_header->destination);
}
