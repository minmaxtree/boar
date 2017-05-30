#ifndef __STACK_H__
#define __STACK_H__

#include "tcp.h"
#include "device.h"

typedef struct boar_stack boar_stack;

typedef void *(* BOAR_STACK_LOOP)(struct boar_stack *);

struct boar_stack {
    BOAR_STACK_LOOP loop;

    boar_dev *dev;
    boar_tcp *tcp;

    uint8_t addr[4];
    uint8_t mac[6];

    boar_list *arp_cache;

    uint8_t netmask[4];
    uint8_t gateway[4];
    uint8_t gateway_mac[6];

    struct tcp_socket **tcp_socks;
    int tcp_sock_cap;
    int tcp_sock_cnt;
    struct udp_socket **udp_socks;
    int udp_sock_cap;
    int udp_sock_cnt;
};

boar_stack *new_boar_stack(uint8_t *gateway, char *cfg_file);

void boar_stack_start(boar_stack *stack);

#endif
