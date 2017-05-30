#include "arp.h"
#include "utils.h"
#include "marshal.h"

#include "ethernet.h"

// assume arpv4
struct proc_out_buf *proc_out_arp(uint8_t *sender_mac_addr, uint8_t *target_mac_addr,
        uint8_t *sender_ip_addr, uint8_t *target_ip_addr, uint8_t *r_mac_addr, uint16_t opcode) {
    struct arp_header arp_header;
    arp_header.hardware_type = 1;  // ethernet
    arp_header.protocol_type = LL_IPV4_T;
    arp_header.hardware_size = 6;
    arp_header.protocol_size = 4;

    arp_header.opcode = opcode;
    memcpy(arp_header.sender_mac_addr, sender_mac_addr, 6);
    memcpy(arp_header.sender_ip_addr, sender_ip_addr, 4);
    memcpy(arp_header.target_mac_addr, target_mac_addr, 6);
    memcpy(arp_header.target_ip_addr, target_ip_addr, 4);

    uint8_t *arp_header_buf = marshal_arp_header(&arp_header);
    return proc_out_ethernet(r_mac_addr, sender_mac_addr, LL_ARP_T,
        arp_header_buf, ARP_HEADER_SIZE);
}

// void boar_arp_proc_input(uint8_t *buf) {
//     struct arp_header *arp_header = unmarshal_arp_header(buf);
//     printf("    [ARP HEADER]\n");
//     print_arp_header(arp_header);

//     if (arp_header->opcode == ARP_REPLY) {
//         struct ares *ares = malloc(sizeof(*ares));
//         memcpy(ares->ip_addr, arp_header->sender_ip_addr, 4);
//         memcpy(ares->mac_addr, arp_header->sender_mac_addr, 6);

//         // if (pthread_rwlock_wrlock(&arp_cache_lock))
//         //     die();
//         arp_cache[arp_cache_count] = ares;
//         if (arp_cache_count++ >= arp_cache_size) {
//             arp_cache_size = 0;
//         }
//         // if (pthread_rwlock_unlock(&arp_cache_lock))
//         //     die();

//     } else if (arp_header->opcode == ARP_REQUEST) {
//         if (ip_addr_eq(arp_header->target_ip_addr, local_ip_addr)) {
//             struct proc_out_buf *proc_out_buf = proc_out_arp(
//                 local_mac_addr, arp_header->sender_mac_addr,
//                 local_ip_addr, arp_header->sender_ip_addr,
//                 local_mac_addr, ARP_REPLY
//             );
//             write(fd, proc_out_buf->buf, proc_out_buf->len);
//             free(proc_out_buf->buf);
//             free(proc_out_buf);
//         }
//     }
// }

void print_arp_header(struct arp_header *arp_header) {
    printf("    hardware_type: %u\n", arp_header->hardware_type);
    printf("    protocl_type: %u\n", arp_header->protocol_type);
    printf("    hardware_size: %u\n", arp_header->hardware_size);
    printf("    protocol_size: %u\n", arp_header->protocol_size);
    printf("    opcode: %u\n", arp_header->opcode);
    printf("    sender_mac_addr: "); print_mac_addr(arp_header->sender_mac_addr);
    printf("    sender_ip_addr: "); print_ip_addr(arp_header->sender_ip_addr);
    printf("    target_mac_addr: "); print_mac_addr(arp_header->target_mac_addr);
    printf("    target_ip_addr: "); print_ip_addr(arp_header->target_ip_addr);
}

uint8_t *marshal_arp_header(struct arp_header *arp_header) {
    uint8_t *buf = malloc(ARP_HEADER_SIZE);
    uint8_t *ptr = buf;
    marshal16(arp_header->hardware_type, ptr);
    ptr += 2;
    marshal16(arp_header->protocol_type, ptr);
    ptr += 2;
    marshal8(arp_header->hardware_size, ptr);
    ptr += 1;
    marshal8(arp_header->protocol_size, ptr);
    ptr += 1;
    marshal16(arp_header->opcode, ptr);
    ptr += 2;
    memcpy(ptr, arp_header->sender_mac_addr, 6);
    ptr += 6;
    memcpy(ptr, arp_header->sender_ip_addr, 4);
    ptr += 4;
    memcpy(ptr, arp_header->target_mac_addr, 6);
    ptr += 6;
    memcpy(ptr, arp_header->target_ip_addr, 4);
    ptr += 4;

    return buf;
}

struct arp_header *unmarshal_arp_header(uint8_t *ptr) {
    struct arp_header *arp_header = malloc(sizeof(*arp_header));
    arp_header->hardware_type = unmarshal16(ptr);
    ptr += 2;
    arp_header->protocol_type = unmarshal16(ptr);
    ptr += 2;
    arp_header->hardware_size = unmarshal8(ptr);
    ptr += 1;
    arp_header->protocol_size = unmarshal8(ptr);
    ptr += 1;
    arp_header->opcode = unmarshal16(ptr);
    ptr += 2;
    memcpy(arp_header->sender_mac_addr, ptr, 6);
    ptr += 6;
    memcpy(arp_header->sender_ip_addr, ptr, 4);
    ptr += 4;
    memcpy(arp_header->target_mac_addr, ptr, 6);
    ptr += 6;
    memcpy(arp_header->target_ip_addr, ptr, 4);

    return arp_header;
}
