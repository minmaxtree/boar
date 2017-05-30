#include "ethernet.h"
#include "utils.h"
#include "marshal.h"

struct proc_out_buf *proc_out_ethernet(uint8_t *dst_addr, uint8_t *src_addr, uint16_t type,
        uint8_t *packet, uint16_t packet_len) {
    struct ethernet_header ethernet_header;
    memcpy(ethernet_header.dst_addr, dst_addr, 6);
    memcpy(ethernet_header.src_addr, src_addr, 6);
    ethernet_header.type = type;
    uint8_t *ethernet_header_buf = marshal_ethernet_header(&ethernet_header);

    uint32_t ethernet_frame_len = ETHERNET_HEADER_SIZE + packet_len;
    uint8_t *ethernet_frame = realloc(ethernet_header_buf, ethernet_frame_len);
    if (!ethernet_frame)
        die();
    memcpy(ethernet_frame + ETHERNET_HEADER_SIZE, packet, packet_len);

    struct proc_out_buf *proc_out_buf = malloc(sizeof(*proc_out_buf));
    proc_out_buf->buf = ethernet_frame;
    proc_out_buf->len = ethernet_frame_len;
    return proc_out_buf;
}

uint8_t *marshal_ethernet_header(struct ethernet_header *ethernet_header) {
    uint8_t *buf = malloc(ETHERNET_HEADER_SIZE);
    uint8_t *ptr = buf;
    memcpy(ptr, ethernet_header->dst_addr, 6);
    ptr += 6;
    memcpy(ptr, ethernet_header->src_addr, 6);
    ptr += 6;
    marshal16(ethernet_header->type, ptr);
    ptr += 2;

    return buf;
}

struct ethernet_header *unmarshal_ethernet_header(uint8_t *ptr) {
    struct ethernet_header *ethernet_header = malloc(sizeof(*ethernet_header));
    memcpy(ethernet_header->dst_addr, ptr, 6);
    ptr += 6;
    memcpy(ethernet_header->src_addr, ptr, 6);
    ptr += 6;
    ethernet_header->type = unmarshal16(ptr);
    ptr += 2;

    return ethernet_header;
}

void print_ethernet_header(struct ethernet_header *ethernet_header) {
    printf("dst_addr: "); print_mac_addr(ethernet_header->dst_addr);
    printf("src_addr: "); print_mac_addr(ethernet_header->src_addr);
    printf("type %u\n", ethernet_header->type);
}

// static struct ethernet_header *new_ethernet_header(uint8_t *l_addr,
//         uint8_t *r_addr, uint16_t type) {
//     struct ethernet_header *ethernet_header = malloc(sizeof(*ethernet_header));
//     memcpy(ethernet_header->dst_addr, r_addr, 6);
//     memcpy(ethernet_header->src_addr, l_addr, 6);
//     ethernet_header->type = type;

//     return ethernet_header;
// }
