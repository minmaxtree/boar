#include "ip.h"
#include "utils.h"
#include "marshal.h"

// ip options not supported
struct proc_out_buf *proc_out_ip(uint8_t *l_ip_addr, uint8_t *r_ip_addr,
        uint8_t *l_mac_addr, uint8_t *r_mac_addr,
        uint8_t proto, uint8_t *seg, uint16_t seg_len) {
    struct ip_header ip_header;
    ip_header.version = 4;
    ip_header.header_length = IP_HEADER_SIZE / 4;
    ip_header.differentiated_services = 0;
    ip_header.checksum = 0;
    ip_header.dont_fragment = 1;
    ip_header.more_fragments = 0;
    ip_header.fragment_offset = 0;
    ip_header.time_to_live = 64;

    ip_header.id = 0;

    ip_header.total_len = IP_HEADER_SIZE + seg_len;
    ip_header.protocol = proto;
    memcpy(ip_header.source, l_ip_addr, 4);
    memcpy(ip_header.destination, r_ip_addr, 4);

    uint8_t *ip_header_buf = marshal_ip_header2(&ip_header);
    uint8_t *ip_packet = realloc(ip_header_buf, ip_header.total_len);
    if (!ip_packet)
        die();
    memcpy(ip_packet + IP_HEADER_SIZE, seg, seg_len);

    return proc_out_ethernet(r_mac_addr, l_mac_addr, LL_IPV4_T,
        ip_packet, ip_header.total_len);
}

int ip_addr_eq(uint8_t *ip_addr1, uint8_t *ip_addr2) {
    for (int i = 0; i < 4; i++)
        if (ip_addr1[i] != ip_addr2[i])
            return 0;
    return 1;
}

uint8_t *marshal_ip_header(struct ip_header *ip_header) {
    uint8_t *buf = malloc(IP_HEADER_SIZE);
    uint8_t *ptr = buf;
    *ptr = (ip_header->version << 4) + ip_header->header_length;
    ptr += 1;
    marshal8(ip_header->differentiated_services, ptr);
    ptr += 1;
    marshal16(ip_header->total_len, ptr);
    ptr += 2;
    marshal16(ip_header->id, ptr);
    ptr += 2;
    // marshal8(ip_header->flags, ptr);
    // ptr += 1;
    // marshal16(ip_header->fragment_offset, ptr);
    // ptr += 1;
    uint16_t ffo = (ip_header->dont_fragment << 14) + (ip_header->more_fragments << 13) +
            ip_header->fragment_offset;
    marshal16(ffo, ptr);
    ptr += 2;

    marshal8(ip_header->time_to_live, ptr);
    ptr += 1;
    marshal8(ip_header->protocol, ptr);
    ptr += 1;
    marshal16(ip_header->checksum, ptr);
    ptr += 2;
    memcpy(ptr, ip_header->source, 4);
    ptr += 4;
    memcpy(ptr, ip_header->destination, 4);
    ptr += 4;

    return buf;
}

uint8_t *marshal_ip_header2(struct ip_header *ip_header) {
    uint8_t *buf = marshal_ip_header(ip_header);
    ip_header->checksum = cksum(buf, IP_HEADER_SIZE);
    free(buf);
    return marshal_ip_header(ip_header);
}

struct ip_header *unmarshal_ip_header(uint8_t *ptr) {
    struct ip_header *ip_header = malloc(sizeof(*ip_header));
    ip_header->version = *ptr >> 4;
    ip_header->header_length = *ptr & 15; // *ptr & 0b1111
    ptr += 1;
    ip_header->differentiated_services = unmarshal8(ptr);
    ptr += 1;
    ip_header->total_len = unmarshal16(ptr);
    ptr += 2;
    ip_header->id = unmarshal16(ptr);
    ptr += 2;
    // ip_header->flags = unmarshal8(ptr);
    // ptr += 1;
    // ip_header->flags_offset = unmarshal8(ptr);
    // ptr += 1;
    uint16_t ffo = unmarshal16(ptr);
    ptr += 2;
    ip_header->dont_fragment = (ffo >> 14) & 1;
    ip_header->more_fragments = (ffo >> 13) & 1;
    ip_header->fragment_offset = ffo & 0x1fff;

    ip_header->time_to_live = unmarshal8(ptr);
    ptr += 1;
    ip_header->protocol = unmarshal8(ptr);
    ptr += 1;
    ip_header->checksum = unmarshal16(ptr);
    ptr += 2;
    memcpy(ip_header->source, ptr, 4);
    ptr += 4;
    memcpy(ip_header->destination, ptr, 4);
    ptr += 4;

    return ip_header;
}

void print_ip_header(struct ip_header *ip_header) {
    printf("    version: %u\n", ip_header->version);
    printf("    header_length: %u\n", ip_header->header_length);
    printf("    differentiated_services: %u\n", ip_header->differentiated_services);
    printf("    total_len: %u\n", ip_header->total_len);
    printf("    id: %u\n", ip_header->id);
    // printf("    flags: %u\n", ip_header->flags);
    // printf("    flags_offset: %u\n", ip_header->flags_offset);
    printf("    flags:\n");
    printf("        dont_fragment: %u\n", ip_header->dont_fragment);
    printf("        more_fragments: %u\n", ip_header->more_fragments);
    printf("    fragment_offset: %u\n", ip_header->fragment_offset);

    printf("    time_to_live: %u\n", ip_header->time_to_live);
    printf("    protocol: %u\n", ip_header->protocol);
    printf("    checksum: %u\n", ip_header->checksum);
    printf("    source: "); print_ip_addr(ip_header->source);
    printf("    destination: "); print_ip_addr(ip_header->destination);
}

// static void *new_ip_header(uint8_t *l_addr, uint8_t *r_addr, uint8_t prot) {
//     struct ip_header *ip_header = malloc(sizeof(*ip_header));
//     ip_header->version = 4;
//     ip_header->header_length = IP_HEADER_SIZE / 4;
//     ip_header->differentiated_services = 0;
//     ip_header->total_len = IP_HEADER_SIZE;
//     ip_header->id = 0;
//     ip_header->dont_fragment = 1;
//     ip_header->more_fragments = 0;
//     ip_header->fragment_offset = 0;
//     ip_header->time_to_live = 0;
//     ip_header->protocol = prot;
//     memcpy(ip_header->source, l_addr, 4);
//     memcpy(ip_header->destination, r_addr, 4);

//     ip_header->checksum = 0;

//     return ip_header;
// }
