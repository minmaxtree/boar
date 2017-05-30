#ifndef __SOCKET_H__
#define __SOCKET_H__

#include "boar.h"

struct udp_socket {
    uint8_t r_ip_addr[4];
    uint16_t r_port;
    uint8_t l_ip_addr[4];
    uint16_t l_port;

    uint8_t l_mac_addr[6];
    uint8_t r_mac_addr[6];

    bool output_comes;
    bool input_comes;
};

enum tcp_state {
    TS_OPEN,  // active open
    TS_CLOSED,
    TS_LISTEN,
    TS_SYN_SENT,
    TS_SYN_RCVD,
    TS_ESTAB,
};

struct tcp_socket {
    uint8_t r_ip_addr[4];
    uint16_t r_port;
    uint8_t l_ip_addr[4];
    uint16_t l_port;

    uint8_t l_mac_addr[6];
    uint8_t r_mac_addr[6];

    enum tcp_state state;
    uint32_t seq_num;
    uint32_t ack_num;

    bool output_comes;
    bool input_comes;
};

enum socket_type {
    ST_TCP,
    ST_UDP,
};

// int br_tcp_socket();
// void bind_tcp(int socknum, uint16_t port);
// void br_listen(int socknum);
// void br_connect(int socknum);
// ssize_t send_tcp(int socknum, char *buf, size_t len);

// int br_udp_socket(enum socket_type st);
// void send_udp(int socknum, char *buf, size_t len, uint8_t *r_ip_addr, uint16_t r_port);
// void bind_udp(int socknum, uint16_t port);
// ssize_t recv_udp(int socknum, char *buf, size_t len);

#endif
