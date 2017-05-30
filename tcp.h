#ifndef __TCP_H__
#define __TCP_H__

#include "boar.h"
#include "boar_list.h"
#include "boar_queue.h"

#define TCP_HEADER_SIZE 20  // size excluding options
struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t header_length: 4;
    struct {
        uint8_t nonce: 1;
        uint8_t congestion_window_reduced: 1;
        uint8_t ecn_echo: 1;
        uint8_t urgent: 1;
        uint8_t ack: 1;
        uint8_t push: 1;
        uint8_t reset: 1;
        uint8_t syn: 1;
        uint8_t fin: 1;
    } flags;  // 12 bits, highest 3 bits reserved
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
    // void *options;
    struct {
        bool has_max_seg_size;
        bool has_sack_permitted_option;
        bool has_timestamp;
        bool has_window_scale;

        uint16_t max_seg_size;
        // bool sack_permitted_option;
        uint64_t timestamp;
        uint8_t window_scale;
    } options;
};

enum tcp_option_kind {
    TCP_OPTION_END_OF_OPTION_LIST = 0,
    TCP_OPTION_NO_OP = 1,
    TCP_OPTION_MAX_SEG_SIZE = 2,
    TCP_OPTION_WINDOW_SCALE = 3,
    TCP_OPTION_SACK_PERMITTED_OPTION = 4,
    TCP_OPTION_TIME_STAMP_OPTION = 8,
};

struct proc_out_buf *proc_out_tcp(struct tcp_socket *tcp_socket);

uint8_t *marshal_tcp_header(struct tcp_header *tcp_header);
struct tcp_header *unmarshal_tcp_header(uint8_t *ptr);
void print_tcp_header(struct tcp_header *tcp_header);

typedef struct {
    boar_list *tcb_list;
    // boar_ip *ip;
    int (*send)(void *stack, uint8_t *raddr, uint8_t *buf, uint32_t len);
    void *stack;
} boar_tcp;

boar_tcp *new_boar_tcp(void *stack,
    int (*send)(void *stack, uint8_t *raddr, uint8_t *buf, uint32_t len));

typedef enum tcp_error {
    OK,
    ERRNOCONN = 1,  // connection does not exist
    ERRCONNEXI,  // connection exists
    ERRINSUFRES,  // insufficient resources
    ERRCONNCLOSING,
    ERRNOFSOCK,
    ERRCLOSING,
    ERRCONNRST,
    ERRCONNREFUSED,
    ERRCONNUTIMEOUT,
} tcp_error;

typedef void (*CALLBACK)(tcp_error err);

void boar_tcp_seg_arv(
    boar_tcp *boar_tcp,
    uint8_t *l_addr,
    uint8_t *r_addr,
    uint8_t *buf,
    uint8_t len
);

void boar_tcp_open(
    boar_tcp *boar_tcp,
    uint8_t *l_addr,
    uint16_t l_port,
    uint8_t *r_addr,
    uint16_t r_port, 
    int active,
    CALLBACK cb
);

void boar_tcp_send(
    boar_tcp *boar_tcp,
    uint16_t l_port,
    uint8_t *r_addr,
    uint16_t r_port,
    uint8_t *buf,
    uint8_t len,
    CALLBACK cb
);

void boar_tcp_close(
    boar_tcp *boar_tcp,
    uint16_t l_port,
    uint8_t *r_addr,
    uint16_t r_port,
    CALLBACK cb
);

void boar_tcp_check_rtto(boar_tcp *boar_tcp);
void boar_tcp_check_twto(boar_tcp *boar_tcp);
void boar_tcp_check_uto(boar_tcp *boar_tcp);

#endif
