#ifndef __BOAR_H__
#define __BOAR_H__

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include <sys/mman.h>
#include <sys/shm.h>

#include <semaphore.h>

#include <pthread.h>

#include "socket.h"
#include "device.h"

#define die() do { fprintf(stderr, "%s:%d:%s:", __FILE__, __LINE__, __func__); \
    perror(""); exit(-1); } while (0)

#define BUF_SIZE 4096
uint8_t boar_output_buf[BUF_SIZE];
int boar_output_len;
uint8_t boar_input_buf[BUF_SIZE];
int boar_input_len;

extern uint8_t broadcast_mac_addr[];

// struct udp_socket **udp_socket_list;
// int socket_count;

// struct tcp_socket **tcp_socket_list;
// int tcp_socket_count;

uint16_t cksum(uint8_t *cs_buf, int cs_buf_sz);

// void *boar_stack(void *);

struct proc_out_buf {
    uint8_t *buf;
    uint32_t len;
};

enum link_layer_type {
    LL_ARP_T = 0x0806,
    LL_IPV4_T = 0x0800,
};

enum transport_layer_type {
    TL_ICMP_T = 1,
    TL_TCP_T = 6,
    TL_UDP_T = 17,
};

#endif
