#include "icmp.h"
#include "marshal.h"

uint8_t *marshal_icmp_header(struct icmp_header *icmp_header) {
    uint8_t *buf = malloc(ICMP_HEADER_SIZE);
    uint8_t *ptr = buf;
    ptr = marshal8_mp(icmp_header->type, ptr);
    ptr = marshal8_mp(icmp_header->code, ptr);
    ptr = marshal16_mp(icmp_header->checksum, ptr);
    ptr = marshal16_mp(icmp_header->id, ptr);
    ptr = marshal16_mp(icmp_header->seq_num, ptr);
    memcpy(ptr, icmp_header->timestamp, 8);
    ptr += 8;

    return buf;
}

struct icmp_header *unmarshal_icmp_header(uint8_t *ptr) {
    struct icmp_header *icmp_header = malloc(sizeof(*icmp_header));
    icmp_header->type = unmarshal8_mp(&ptr);
    icmp_header->code = unmarshal8_mp(&ptr);
    icmp_header->checksum = unmarshal16_mp(&ptr);
    icmp_header->id = unmarshal16_mp(&ptr);
    icmp_header->seq_num = unmarshal16_mp(&ptr);
    memcpy(icmp_header->timestamp, ptr, 8);
    ptr += 8;

    return icmp_header;
}

void print_icmp_header(struct icmp_header *icmp_header) {
    printf("        type: %u\n", icmp_header->type);
    printf("        code: %u\n", icmp_header->code);
    printf("        checksum: %u\n", icmp_header->checksum);
    printf("        id: %u\n", icmp_header->id);
    printf("        seq_num: %u\n", icmp_header->seq_num);
    printf("        timestamp: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", icmp_header->timestamp[i]);
    }
    printf("\n");
}
