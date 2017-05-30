#include "boar.h"
#include "stack.h"

#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"
#include "marshal.h"
#include "utils.h"

int mac_addr_eq(uint8_t *mac_addr1, uint8_t *mac_addr2) {
    for (int i = 0; i < 6; i++)
        if (mac_addr1[i] != mac_addr2[i])
            return 0;
    return 1;
}

uint8_t local_mac_addr[] = { 0x1a, 0x11, 0x99, 0xe7, 0x4d, 0x80}; // hard-coded TAP100 mac address
uint8_t local_ip_addr[]  = { 192, 168, 5, 100 };

struct boar_stack *stack_init() {
    struct boar_stack *stack = malloc(sizeof(*stack));
    stack->udp_sock_cap = 1024;
    stack->udp_sock_cnt = 0;
    stack->udp_socks = malloc(
        sizeof(*stack->udp_socks) * stack->udp_sock_cap);
    stack->tcp_sock_cap = 1024;
    stack->tcp_sock_cnt = 0;
    stack->tcp_socks = malloc(
        sizeof(*stack->tcp_socks) * stack->tcp_sock_cap);

    return stack;
}

// struct udp_socket *poll_sockets() {
//     for (int i = 0; i < stack->udp_sock_cnt; i++) {
//         if (stack->udp_socks[i]->input_comes) {
//             return stack->udp_socks[i];
//         }
//     }
//     return 0;
// }

// struct tcp_socket *poll_tcp_socket() {
//     for (int i = 0; i < stack->tcp_sock_cnt; i++) {
//         if (stack->tcp_socks[i]->state == TS_OPEN) {
//             return stack->tcp_socks[i];
//         }
//     }
//     return 0;
// }

struct ares {
    uint8_t ip_addr[4];
    uint8_t mac_addr[6];
};

// #define ARP_CACHE_SIZE 1024
// int arp_cache_size = ARP_CACHE_SIZE;
// int arp_cache_count;
// struct ares *arp_cache[ARP_CACHE_SIZE];

void do_arp(boar_stack *stack, int fd, uint8_t *l_mac_addr, uint8_t *l_ip_addr,
        uint8_t *ip_addr, uint8_t *mac_addr) {
    while (true) {
        // for (int i = 0; i < arp_cache_count; i++) {
        //     if (!memcmp(arp_cache[i]->ip_addr, ip_addr, 4)) {
        //         memcpy(mac_addr, arp_cache[i]->mac_addr, 0);
        //         break;
        //     }
        // }

        struct proc_out_buf *proc_out_buf = proc_out_arp(l_mac_addr, broadcast_mac_addr,
            l_ip_addr, ip_addr, broadcast_mac_addr, ARP_REQUEST);
        // write(fd, proc_out_buf->buf, proc_out_buf->len);
        boar_dev_write(stack->dev, proc_out_buf->buf, proc_out_buf->len);
        free(proc_out_buf->buf);
        free(proc_out_buf);
    }
}

// static void *arp_cache_lookup(boar_stack *stack, uint8_t *addr) {
//     boar_list_node *ptr;
//     for (ptr = stack->arp_cache->head; ptr; ptr = ptr->next) {
//         struct ares *ares = ptr->value;
//         if (ip_addr_eq(addr, ares->ip_addr))
//             return ares->mac_addr;
//     }
//     return 0;
// }

static void *boar_stack_loop(boar_stack *stack);

static int boar_stack_tcp_send(void *vptr,
        uint8_t *r_addr, uint8_t *buf, uint32_t len) {
    boar_stack *stack = vptr;
    // uint8_t *r_mac = arp_cache_lookup(stack, r_addr);
    // if (!r_mac) {
    //     return -1;

    //     struct proc_out_buf *proc_out_buf = proc_out_arp(stack->mac, broadcast_mac_addr,
    //         stack->addr, r_addr, broadcast_mac_addr, ARP_REQUEST);
    //     boar_dev_write(stack->dev, proc_out_buf->buf, proc_out_buf->len);
    //     free(proc_out_buf->buf);
    //     free(proc_out_buf);
    // }

    struct proc_out_buf *proc_out_buf = proc_out_ip(
        stack->addr, r_addr, stack->mac, stack->gateway_mac, TL_TCP_T, buf, len);
    boar_dev_write(stack->dev, proc_out_buf->buf, proc_out_buf->len);
    free(proc_out_buf->buf);
    free(proc_out_buf);

    return len;
}

uint8_t DEFAULT_NETMASK[] = { 255, 255, 255, 0 };

static int read_dev_cfg_ln(int fd, boar_dev_cfg *dev_cfg) {
    char field[128];
    char *ptr = field;
    while (1) {
        int n = read(fd, ptr, 1);
        if (n != 1)
            return 0;
        if (*ptr == ' ') {
            *ptr = 0;
            break;
        }
        ptr++;
    }

    char value[128];
    ptr = value;
    while (1) {
        int n = read(fd, ptr, 1);
        if (n != 1)
            return 0;
        if (*ptr == '\n') {
            *ptr = 0;
            break;
        }
        ptr++;
    }

    if (!strcmp(field, "interface"))
        strcpy(dev_cfg->interface, value);
    else if (!strcmp(field, "address"))
        strcpy(dev_cfg->address, value);

    return 1;
}

static void read_dev_cfg(char *fname, boar_dev_cfg *dev_cfg) {
    int fd = open(fname, O_RDONLY);
    while (1) {
        if (!read_dev_cfg_ln(fd, dev_cfg))
            break;
    }
}

static void ip_addr_stou8(uint8_t *result, char *addr) {
    char *ptr = addr;
    char buf[8];
    for (int i = 0; i < 4; i++) {
        result[i] = 0;
        char *bufp = buf;
        while (1) {
            if (*ptr == '.' || *ptr == 0) {
                *bufp = 0;
                ptr++;
                break;
            } else {
                *bufp = *ptr;
                bufp++;
                ptr++;
            }
        }
        int base = 1;
        for (int j = strlen(buf) - 1; j >= 0; j--) {
            result[i] += (buf[j] - '0') * base;
            base *= 10;
        }
    }
}

boar_stack *new_boar_stack(uint8_t *gateway, char *cfg_file) {
    boar_stack *stack = malloc(sizeof(*stack));
    stack->loop = boar_stack_loop;

    boar_dev_cfg dev_cfg;
    printf("1\n");
    read_dev_cfg(cfg_file, &dev_cfg);
    printf("dev_cfg.interface is %s\n", dev_cfg.interface);
    printf("dev_cfg.address is %s\n", dev_cfg.address);
    stack->dev = new_boar_dev(&dev_cfg);
    stack->tcp = new_boar_tcp(stack, boar_stack_tcp_send);

    memcpy(stack->addr, local_ip_addr, 4);
    memcpy(stack->mac, local_mac_addr, 6);

    stack->arp_cache = new_boar_list();

    memcpy(stack->netmask, DEFAULT_NETMASK, 4);
    ip_addr_stou8(stack->gateway, dev_cfg.address);
    // memcpy(stack->gateway, gateway, 4);

    return stack;
}

void boar_stack_start(boar_stack *stack) {
    struct proc_out_buf *proc_out_buf = proc_out_arp(stack->mac, broadcast_mac_addr,
        stack->addr, stack->gateway, broadcast_mac_addr, ARP_REQUEST);
    boar_dev_write(stack->dev, proc_out_buf->buf, proc_out_buf->len);
    free(proc_out_buf->buf);
    free(proc_out_buf);

    stack->loop(stack);
}

// void *boar_stack_output(void *vptr) {
//     int fd = *(int *)vptr;

//     while (1) {
//         struct udp_socket *udp_socket = poll_sockets();
//         if (udp_socket) {
//             uint8_t dst_mac_addr[6];
//             do_arp(fd, local_mac_addr, local_ip_addr, udp_socket->r_ip_addr, dst_mac_addr);
//             memcpy(udp_socket->l_mac_addr, local_mac_addr, 6);
//             memcpy(udp_socket->r_mac_addr, dst_mac_addr, 6);

//             struct proc_out_buf *proc_out_buf = proc_out_udp(udp_socket);
//             write(fd, proc_out_buf->buf, proc_out_buf->len);
//             free(proc_out_buf->buf);
//             free(proc_out_buf);
//         }

//         struct tcp_socket *tcp_socket = poll_tcp_socket();
//         if (tcp_socket) {
//             uint8_t dst_mac_addr[6];
//             do_arp(fd, local_mac_addr, local_ip_addr, udp_socket->r_ip_addr, dst_mac_addr);
//             memcpy(udp_socket->l_mac_addr, local_mac_addr, 6);
//             memcpy(udp_socket->r_mac_addr, dst_mac_addr, 6);

//             struct proc_out_buf *proc_out_buf = proc_out_tcp(tcp_socket);
//             write(fd, proc_out_buf->buf, proc_out_buf->len);
//             free(proc_out_buf->buf);
//             free(proc_out_buf);
//         }
//     }

//     return 0;
// }

static void proc_arp(boar_stack *stack, uint8_t *datap) {
    struct arp_header *arp_header = unmarshal_arp_header(datap);
    // printf("    [ARP HEADER]\n");
    // print_arp_header(arp_header);

    if (arp_header->opcode == ARP_REPLY) {

        // if (pthread_rwlock_wrlock(&arp_cache_lock))
        //     die();
        // arp_cache[arp_cache_count] = ares;
        // if (arp_cache_count++ >= arp_cache_size) {
        //     arp_cache_size = 0;
        // }

        boar_list_node *ptr;
        int entry_exists = 0;
        for (ptr = stack->arp_cache->head; ptr; ptr = ptr->next) {
            struct ares *ares = ptr->value;
            if (ip_addr_eq(arp_header->sender_ip_addr, ares->ip_addr)) {
                memcpy(ares->mac_addr, arp_header->sender_mac_addr, 6);
                entry_exists = 1;
                break;
            }
        }
        if (!entry_exists) {
            struct ares *ares = malloc(sizeof(*ares));
            memcpy(ares->ip_addr, arp_header->sender_ip_addr, 4);
            memcpy(ares->mac_addr, arp_header->sender_mac_addr, 6);

            boar_list_push(stack->arp_cache, ares);
        }

        // if (pthread_rwlock_unlock(&arp_cache_lock))
        //     die();

        if (ip_addr_eq(stack->gateway, arp_header->sender_ip_addr))
            memcpy(stack->gateway_mac, arp_header->sender_mac_addr, 6);

    } else if (arp_header->opcode == ARP_REQUEST) {
        if (ip_addr_eq(arp_header->target_ip_addr, local_ip_addr)) {
            struct proc_out_buf *proc_out_buf = proc_out_arp(
                local_mac_addr, arp_header->sender_mac_addr,
                local_ip_addr, arp_header->sender_ip_addr,
                local_mac_addr, ARP_REPLY
            );
            // write(fd, proc_out_buf->buf, proc_out_buf->len);
            boar_dev_write(stack->dev, proc_out_buf->buf, proc_out_buf->len);
            free(proc_out_buf->buf);
            free(proc_out_buf);
        }
    }
}

static void proc_udp(boar_stack *stack, uint8_t *datap) {
    struct udp_header *udp_header = unmarshal_udp_header(datap);
    // printf("        [UDP_HEADER]\n");
    // print_udp_header(udp_header);

    uint8_t *udp_data = datap + UDP_HEADER_SIZE;
    // printf("        <UDP_DATA>\n");
    // printf("        %s\n", udp_data);

    for (int i = 0; i < stack->udp_sock_cnt; i++) {
        if (stack->udp_socks[i]->l_port == udp_header->dst_port) {
            memcpy(boar_output_buf, udp_data, udp_header->length -
                UDP_HEADER_SIZE);
            boar_output_len = udp_header->length - UDP_HEADER_SIZE;
            stack->udp_socks[i]->output_comes = true;
            break;
        }
    }
}

static void proc_icmp(boar_stack *stack, uint8_t *datap) {
    struct icmp_header *icmp_header = unmarshal_icmp_header(datap);
    // printf("        [ICMP HEADER]\n");
    // print_icmp_header(icmp_header);

    switch (icmp_header->type) {
        case ICMP_ECHO_REQUEST: {
            // // reply ethernet header
            // memcpy(ethernet_header->dst_addr, ethernet_header->src_addr, 6);
            // memcpy(ethernet_header->src_addr, local_mac_addr, 6);
            // uint8_t *ethernet_header_buf = marshal_ethernet_header(ethernet_header);
            // memcpy(buf, ethernet_header_buf, ETHERNET_HEADER_SIZE);

            // // reply ip header
            // memcpy(ip_header->destination, ip_header->source, 4);
            // memcpy(ip_header->source, local_ip_addr, 4);
            // uint8_t *ip_header_buf = marshal_ip_header(ip_header);
            // memcpy(buf + ETHERNET_HEADER_SIZE, ip_header_buf, IP_HEADER_SIZE);

            // // reply icmp header
            // icmp_header->type = ICMP_ECHO_REPLY;
            // icmp_header->checksum = 0;
            // uint8_t *icmp_header_buf = marshal_icmp_header(icmp_header);
            // memcpy(buf + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE,
            //     icmp_header_buf, ICMP_HEADER_SIZE);
            // icmp_header->checksum = cksum(buf + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE,
            //     n - ETHERNET_HEADER_SIZE - IP_HEADER_SIZE);
            // icmp_header_buf = marshal_icmp_header(icmp_header);
            // memcpy(buf + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE,
            //     icmp_header_buf, ICMP_HEADER_SIZE);

            // write(fd, buf, n);
        }
        break;
    }
}

static void *boar_stack_loop(boar_stack *stack) {
    pthread_rwlock_t arp_cache_lock;
    if (pthread_rwlock_init(&arp_cache_lock, 0) < 0)
        die();

    // pthread_t boar_stack_output_thread;
    // pthread_create(&boar_stack_output_thread, 0, boar_stack_output, &fd);

    uint8_t buf[1024];
    while (1) {
        boar_tcp_check_rtto(stack->tcp);
        boar_tcp_check_twto(stack->tcp);
        boar_tcp_check_uto(stack->tcp);

        // ssize_t n = read(fd, buf, 1024);
        ssize_t n = boar_dev_read(stack->dev, buf, 1024);
        if (n < 0) {
            perror("read");
            exit(-1);
        }
        printf("n is %ld\n", n);

        uint8_t *datap = buf;

        struct ethernet_header *ethernet_header = unmarshal_ethernet_header(datap);
        printf("[ETHERNET HEADER]\n");
        print_ethernet_header(ethernet_header);

        datap += ETHERNET_HEADER_SIZE;
        switch (ethernet_header->type) {
            case LL_ARP_T: {
                proc_arp(stack, datap);
            }
            break;
            case LL_IPV4_T: {
                struct ip_header *ip_header = unmarshal_ip_header(datap);
                // printf("    [IPV4 HEADER]\n");
                // print_ip_header(ip_header);

                datap += IP_HEADER_SIZE;
                switch (ip_header->protocol) {
                    case TL_ICMP_T: {
                        proc_icmp(stack, datap);
                    }
                    break;
                    case TL_TCP_T: {
                        int datal = n - (datap - buf);
                        boar_tcp_seg_arv(stack->tcp,
                            ip_header->destination, ip_header->source, datap, datal);
                    }
                    break;
                    case TL_UDP_T: {
                        proc_udp(stack, datap);
                    }
                }
            }
            break;
        }
        // puts("");
    }

    return 0;
}
