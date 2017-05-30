#include "udp.h"
#include "marshal.h"

#include "ip.h"
#include "utils.h"

uint16_t udp_checksum(struct udp_header *udp_header, uint8_t *udp_data,
        uint16_t udp_data_len, uint8_t *src_ip_addr, uint8_t *dst_ip_addr);

struct proc_out_buf *proc_out_udp(struct udp_socket *udp_socket) {
    struct udp_header udp_header;
    udp_header.src_port = udp_socket->l_port;
    udp_header.dst_port = udp_socket->r_port;
    udp_header.length = UDP_HEADER_SIZE + boar_input_len;
    udp_header.checksum = 0;

    udp_header.checksum = udp_checksum(&udp_header, boar_input_buf,
        boar_input_len, udp_socket->l_ip_addr, udp_socket->r_ip_addr);
    uint8_t *udp_header_buf = marshal_udp_header(&udp_header);

    uint8_t *udp_segment = realloc(udp_header_buf, udp_header.length);
    if (!udp_segment)
        die();
    memcpy(udp_segment + UDP_HEADER_SIZE, boar_input_buf, boar_input_len);

    return proc_out_ip(udp_socket->l_ip_addr, udp_socket->r_ip_addr,
        udp_socket->l_mac_addr, udp_socket->r_mac_addr,
        TL_UDP_T, udp_segment, udp_header.length);
}

uint8_t *marshal_udp_header(struct udp_header *udp_header) {
    uint8_t *buf = malloc(UDP_HEADER_SIZE);
    uint8_t *ptr = buf;
    ptr = marshal16_mp(udp_header->src_port, ptr);
    ptr = marshal16_mp(udp_header->dst_port, ptr);
    ptr = marshal16_mp(udp_header->length, ptr);
    ptr = marshal16_mp(udp_header->checksum, ptr);
    return buf;
}

/*! caution: udp_header struct is modified */
uint8_t *marshal_udp_header2(struct udp_header *udp_header) {
    uint8_t *buf = marshal_udp_header(udp_header);
    udp_header->checksum = cksum(buf, UDP_HEADER_SIZE);
    free(buf);
    return marshal_udp_header(udp_header);
}

struct udp_header *unmarshal_udp_header(uint8_t *ptr) {
    struct udp_header *udp_header = malloc(sizeof(*udp_header));
    udp_header->src_port = unmarshal16_mp(&ptr);
    udp_header->dst_port = unmarshal16_mp(&ptr);
    udp_header->length = unmarshal16_mp(&ptr);
    udp_header->checksum = unmarshal16_mp(&ptr);
    return udp_header;
}

void print_udp_header(struct udp_header *udp_header) {
    printf("        src_port: %u\n", udp_header->src_port);
    printf("        dst_port: %u\n", udp_header->dst_port);
    printf("        length: %u\n", udp_header->length);
    printf("        checksum: %u\n", udp_header->checksum);
}

uint16_t udp_checksum(struct udp_header *udp_header, uint8_t *udp_data,
        uint16_t udp_data_len, uint8_t *src_ip_addr, uint8_t *dst_ip_addr) {
    uint16_t old_checksum = udp_header->checksum;
    udp_header->checksum = 0;
    uint8_t *udp_header_buf = marshal_udp_header(udp_header);

    uint8_t segment[udp_header->length];
    memcpy(segment, udp_header_buf, UDP_HEADER_SIZE);
    if (udp_data && udp_data_len > 0)
        memcpy(segment + UDP_HEADER_SIZE, udp_data, udp_data_len);
    uint16_t checksum = segment_checksum(TL_UDP_T, segment, udp_header->length,
        src_ip_addr, dst_ip_addr);
    free(udp_header_buf);

    udp_header->checksum = old_checksum;

    return checksum;
}
