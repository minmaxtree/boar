#include "tcp.h"
#include "marshal.h"

#include "ip.h"
#include "utils.h"
#include "boar_queue.h"
#include "boar_list.h"

#include <sys/time.h>
#include <stdio.h>

typedef struct trans_ctl_blk TCB;

typedef struct {
    uint32_t seq;
    uint32_t ack;
    uint8_t flags;
    uint8_t *data;
    uint32_t len;
    uint16_t wnd;
    int snd_time;
} tcp_seg;

typedef enum {
    ACK = 1 << 0,
    SYN = 1 << 1,
    FIN = 1 << 3,
    RST = 1 << 4,
    PUSH = 1 << 5,
} TCP_CTL_FLG;

typedef enum tcp_conn_state {
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RCVD,
    TCP_ESTAB,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_CLOSING,
    TCP_TIME_WAIT,
} tcp_conn_state;

typedef struct {
    uint8_t *buf;
    int len;
    CALLBACK callback;
    uint32_t sseq;
} receiver;

typedef struct {
    uint8_t *buf;
    int len;
    CALLBACK callback;
    uint32_t sseq;
} sender;

typedef struct trans_ctl_blk {
    uint8_t l_addr[4];
    uint16_t l_port;
    uint8_t r_addr[4];
    uint16_t r_port;

    uint8_t *r_buf;
    uint8_t *s_buf;

    tcp_conn_state state;

    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t snd_wnd;
    uint32_t snd_wl1; // seg seq num use for last winow update
    uint32_t snd_wl2;  // seg ack num use for last winow update
    uint32_t iss;  // initial send sequence number

    uint32_t rcv_nxt;
    uint32_t rcv_wnd;
    uint32_t irs;  // initial receive seqeunce number

    uint32_t seg_seq;
    uint32_t seg_ack;
    uint32_t seg_len;
    uint32_t seg_wnd;

    boar_queue *rtqueue;  // retransimssion queue

    boar_queue *tqueue;
    boar_queue *rqueue;

    boar_queue *rcvq;
    boar_queue *sndq;

    int srtt;  // smoothed round-trip time

    int rtto;  // retransmission timeout
    int rtt_start;
    int rtt_on;
    int twto;
    int twt_start;
    int twt_on;

    int active;

    CALLBACK open_cb;

    CALLBACK close_cb;
    int close_queued;
} TCB;

static void tcp_rst_seg(boar_tcp *boar_tcp, TCB *tcb, tcp_seg *seg);
static uint32_t get_iss();
static void fill_fields(TCB *tcb, uint8_t *r_addr, uint16_t r_port);
static void rcv_ack(TCB *tcb, uint32_t ack);
static void notify_users(TCB *tcb, tcp_error err);
static int fin_acked(TCB *tcb);
static void rtqueue_flush(boar_tcp *boar_tcp, TCB *tcb);
static void sndq_flush(boar_tcp *boar_tcp, TCB *tcb);
static void flush(boar_tcp *boar_tcp, TCB *tcb);
static int get_curtime();
static int tcb_rtto(TCB *tcb);
static int tcb_twto(TCB *tcb);
static void start_retrans_timer(TCB *tcb);
static void start_time_wait_timer(TCB *tcb);
static void turn_off_timers(TCB *tcb);
static tcp_seg *new_tcp_seg(uint32_t seq, uint32_t ack, uint8_t flags,
    uint8_t *data, uint32_t len);
static void free_tcp_seg(tcp_seg *seg);
static receiver *new_receiver(uint8_t *buf, int len, CALLBACK cb);
static tcp_seg *segmentize(TCB *tcb, uint8_t *ptr, int len, int push);
static int rqueue_is_empty(TCB *tcb);
// static int tqueue_is_empty(TCB *tcb);
static void notify_rcvs(TCB *tcb, tcp_error err);
static void notify_snds(TCB *tcb, tcp_error err);
static void update_rtto(TCB *tcb, int rtt);
static void rst_queued_rcvs(TCB *tcb);
static void rst_queued_snds(TCB *tcb);
// static void rtqueue_remove(TCB *tcb, uint32_t ack);
static void rtqueue_remove_and_update_rtto(TCB *tcb);
static void rtqueue_remove_all(TCB *tcb);
static inline int is_zero_addr(uint8_t *addr);
static TCB *boar_tcp_find_tcb(boar_tcp *boar_tcp, uint16_t l_port,
    uint8_t *r_addr, uint16_t r_port);
static inline void boar_tcp_add_tcb(boar_tcp *boar_tcp, TCB *tcb);
static inline void boar_tcp_delete_tcb(boar_tcp *boar_tcp, TCB *tcb);
// static inline void boar_tcp_connect(boar_tcp *boar_tcp, TCB *tcb);
static TCB *new_tcb(uint8_t *l_addr, uint16_t l_port, uint8_t *r_addr, uint16_t r_port);
static void free_tcb(TCB *tcb);
static struct tcp_header *new_tcp_header(TCB *tcb);
static void tcp_send_syn_ack(boar_tcp *boar_tcp, TCB *tcb);
static void tcp_send_syn(boar_tcp *boar_tcp, TCB *tcb);
static void tcp_send_rst(boar_tcp *boar_tcp, TCB *tcb);
static void tcp_send_fin(boar_tcp *boar_tcp, TCB *tcb);
static void tcp_send_ack(boar_tcp *boar_tcp, TCB *tcb);
static void tcp_ack_seg(boar_tcp *boar_tcp, TCB *tcb, tcp_seg *seg);
static void tcp_send_ctl(boar_tcp *boar_tcp, TCB *tcb,
    uint32_t esq_num, uint32_t ack_num, uint8_t flags);
static void tcp_close_closed(boar_tcp *boar_tcp, TCB *tcb, tcp_seg *seg);
static void tcp_active_open(boar_tcp *boar_tcp, TCB *tcb);
static void tcp_send(boar_tcp *boar_tcp, TCB *tcb, tcp_seg *seg);
static void tcp_send_buf(boar_tcp *boar_tcp, uint8_t *r_addr,
    uint8_t *buf, int buf_len);
static void signal_user(CALLBACK cb, tcp_error err);
static void notify_opener(TCB *tcb, tcp_error err);
static void notify_closer(TCB *tcb, tcp_error err);
static void tqueue_flush(boar_tcp *boar_tcp, TCB *tcb);
static int rtqueue_is_empty(TCB *tcb);

uint16_t tcp_checksum(struct tcp_header *tcp_header, uint8_t *tcp_data,
        uint16_t tcp_data_len, uint8_t *src_ip_addr, uint8_t *dst_ip_addr);

struct proc_out_buf *proc_out_tcp(struct tcp_socket *tcp_socket) {
    struct tcp_header tcp_header;
    tcp_header.window_size = 0xffff;
    tcp_header.checksum = 0;
    tcp_header.urgent_ptr = 0;

    tcp_header.seq_num = 0;
    tcp_header.ack_num = 0;
    tcp_header.header_length = TCP_HEADER_SIZE / 4;

    tcp_header.src_port = tcp_socket->l_port;
    tcp_header.dst_port = tcp_socket->r_port;

    if (tcp_socket->state == TS_OPEN) {
        tcp_header.flags.syn = 1;
    } else if (tcp_socket->state == TS_LISTEN) {
        tcp_header.flags.syn = 1;
        tcp_header.flags.ack = 1;
    } else if (tcp_socket->state == TS_SYN_SENT) {
        tcp_header.flags.ack = 1;
    }

    tcp_header.seq_num = tcp_socket->seq_num++;
    tcp_header.ack_num = tcp_socket->ack_num;

    tcp_header.checksum = tcp_checksum(&tcp_header, boar_input_buf,
        boar_input_len, tcp_socket->l_ip_addr, tcp_socket->r_ip_addr);
    uint8_t *tcp_header_buf = marshal_tcp_header(&tcp_header);

    uint8_t *tcp_segment = realloc(tcp_header_buf,
        tcp_header.header_length + boar_input_len);
    if (!tcp_segment)
        die();
    memcpy(tcp_segment + TCP_HEADER_SIZE, boar_input_buf, boar_input_len);

    return proc_out_ip(tcp_socket->l_ip_addr, tcp_socket->r_ip_addr,
        tcp_socket->l_mac_addr, tcp_socket->r_mac_addr,
        TL_TCP_T, tcp_segment, tcp_header.header_length + boar_input_len);
}

uint8_t *marshal_tcp_header(struct tcp_header *tcp_header) {
    uint8_t *buf = malloc(tcp_header->header_length * 4);
    uint8_t *ptr = buf;
    ptr = marshal16_mp(tcp_header->src_port, ptr);
    ptr = marshal16_mp(tcp_header->dst_port, ptr);
    ptr = marshal32_mp(tcp_header->seq_num, ptr);
    ptr = marshal32_mp(tcp_header->ack_num, ptr);
    uint16_t flags = (tcp_header->flags.nonce << 8) +
                    (tcp_header->flags.congestion_window_reduced << 7) +
                    (tcp_header->flags.ecn_echo << 6) +
                    (tcp_header->flags.urgent << 5) +
                    (tcp_header->flags.ack << 4) +
                    (tcp_header->flags.push << 3) +
                    (tcp_header->flags.reset << 2) +
                    (tcp_header->flags.syn << 1) +
                    tcp_header->flags.fin;
    ptr = marshal16_mp((tcp_header->header_length << 12) + flags, ptr);
    ptr = marshal16_mp(tcp_header->window_size, ptr);
    ptr = marshal16_mp(tcp_header->checksum, ptr);
    ptr = marshal16_mp(tcp_header->urgent_ptr, ptr);
    // options
    if (tcp_header->options.has_max_seg_size) {
        ptr = marshal8_mp(TCP_OPTION_MAX_SEG_SIZE, ptr);
        ptr = marshal8_mp(4, ptr);
        ptr = marshal16_mp(tcp_header->options.max_seg_size, ptr);
    }
    if (tcp_header->options.has_sack_permitted_option) {
        ptr = marshal8_mp(TCP_OPTION_SACK_PERMITTED_OPTION, ptr);
        ptr = marshal8_mp(2, ptr);
    }
    if (tcp_header->options.has_timestamp) {
        ptr = marshal8_mp(TCP_OPTION_TIME_STAMP_OPTION, ptr);
        ptr = marshal8_mp(10, ptr);
        ptr = marshal64_mp(tcp_header->options.timestamp, ptr);
    }
    if (tcp_header->options.has_window_scale) {
        ptr = marshal8_mp(TCP_OPTION_WINDOW_SCALE, ptr);
        ptr = marshal8_mp(3, ptr);
        ptr = marshal8_mp(tcp_header->options.window_scale, ptr);
    }

    return buf;
}

struct tcp_header *unmarshal_tcp_header(uint8_t *ptr) {
    uint8_t *buf_start = ptr;

    struct tcp_header *tcp_header = malloc(sizeof(*tcp_header));
    tcp_header->src_port = unmarshal16_mp(&ptr);
    tcp_header->dst_port = unmarshal16_mp(&ptr);
    tcp_header->seq_num = unmarshal32_mp(&ptr);
    tcp_header->ack_num = unmarshal32_mp(&ptr);
    uint16_t hlf = unmarshal16_mp(&ptr);
    tcp_header->header_length = hlf >> 12;

    uint8_t *buf_end = buf_start + tcp_header->header_length * 4;

    uint16_t flags = hlf & 0x0fff;
    tcp_header->flags.nonce = flags >> 8;
    tcp_header->flags.congestion_window_reduced = flags >> 7;
    tcp_header->flags.ecn_echo = flags >> 6;
    tcp_header->flags.urgent = flags >> 5;
    tcp_header->flags.ack = flags >> 4;
    tcp_header->flags.push = flags >> 3;
    tcp_header->flags.reset = flags >> 2;
    tcp_header->flags.syn = flags >> 1;
    tcp_header->flags.fin = flags;

    tcp_header->window_size = unmarshal16_mp(&ptr);
    tcp_header->checksum = unmarshal16_mp(&ptr);
    tcp_header->urgent_ptr = unmarshal16_mp(&ptr);
    // options
    tcp_header->options.has_max_seg_size = false;
    tcp_header->options.has_timestamp = false;
    tcp_header->options.has_sack_permitted_option = false;
    tcp_header->options.has_window_scale = false;

    while (ptr < buf_end) {
        uint8_t kind = *ptr++;
        switch (kind) {
            case TCP_OPTION_NO_OP: break;
            case TCP_OPTION_MAX_SEG_SIZE: {
                ptr++;
                tcp_header->options.has_max_seg_size = true;
                tcp_header->options.max_seg_size = unmarshal16_mp(&ptr);
            }
            break;
            case TCP_OPTION_TIME_STAMP_OPTION: {
                ptr++;
                tcp_header->options.has_timestamp = true;
                tcp_header->options.timestamp = unmarshal64_mp(&ptr);
            }
            break;
            case TCP_OPTION_SACK_PERMITTED_OPTION: {
                ptr++;
                tcp_header->options.has_sack_permitted_option = true;
            }
            break;
            case TCP_OPTION_WINDOW_SCALE: {
                ptr++;
                tcp_header->options.has_window_scale = true;
                tcp_header->options.window_scale = unmarshal8_mp(&ptr);
            }
            break;
        }
    }

    return tcp_header;
}

void print_tcp_header(struct tcp_header *tcp_header) {
    printf("        src_port: %u\n", tcp_header->src_port);
    printf("        dst_port: %u\n", tcp_header->dst_port);
    printf("        seq_num: %u\n", tcp_header->seq_num);
    printf("        ack_num: %u\n", tcp_header->ack_num);
    printf("        header_length: %u (%u bytes)\n", tcp_header->header_length, tcp_header->header_length * 4);
    printf("        flags:\n");
    printf("            nonce: %u\n", tcp_header->flags.nonce);
    printf("            congestion_window_reduced: %u\n", tcp_header->flags.congestion_window_reduced);
    printf("            ecn_echo: %u\n", tcp_header->flags.ecn_echo);
    printf("            urgent: %u\n", tcp_header->flags.urgent);
    printf("            ack: %u\n", tcp_header->flags.ack);
    printf("            push: %u\n", tcp_header->flags.push);
    printf("            reset: %u\n", tcp_header->flags.reset);
    printf("            syn: %u\n", tcp_header->flags.syn);
    printf("            fin: %u\n", tcp_header->flags.fin);
    printf("        window_size: %u\n", tcp_header->window_size);
    printf("        checksum: %u\n", tcp_header->checksum);
    printf("        urgent_ptr: %u\n", tcp_header->urgent_ptr);
    // options
    printf("        options:\n");
    if (tcp_header->options.has_max_seg_size)
        printf("            max_seg_size: %u\n", tcp_header->options.max_seg_size);
    if (tcp_header->options.has_sack_permitted_option)
        printf("            sack_permitted_option: true\n");
    if (tcp_header->options.has_timestamp)
        printf("            timestamp: 0x%08lx\n", tcp_header->options.timestamp);
    if (tcp_header->options.has_window_scale)
        printf("            window_scale: %u\n", tcp_header->options.window_scale);
}

uint16_t tcp_checksum(struct tcp_header *tcp_header, uint8_t *tcp_data,
        uint16_t tcp_data_len, uint8_t *src_ip_addr, uint8_t *dst_ip_addr) {
    uint16_t old_checksum = tcp_header->checksum;
    tcp_header->checksum = 0;
    uint8_t *tcp_header_buf = marshal_tcp_header(tcp_header);

    int header_len = tcp_header->header_length * 4;
    uint8_t segment[header_len + tcp_data_len];
    memcpy(segment, tcp_header_buf, header_len);
    if (tcp_data && tcp_data_len > 0)
        memcpy(segment + header_len, tcp_data, tcp_data_len);
    uint16_t checksum = segment_checksum(TL_TCP_T, segment, header_len + tcp_data_len,
        src_ip_addr, dst_ip_addr);
    free(tcp_header_buf);

    tcp_header->checksum = old_checksum;

    return checksum;
}

boar_tcp *new_boar_tcp(void *stack,
        int (*send)(void *stack, uint8_t *raddr, uint8_t *buf, uint32_t len)) {
    boar_tcp *boar_tcp = malloc(sizeof(*boar_tcp));
    boar_tcp->tcb_list = new_boar_list();
    boar_tcp->stack = stack;
    boar_tcp->send = send;
    return boar_tcp;
}

void boar_tcp_open(
    boar_tcp *boar_tcp,
    uint8_t *l_addr,
    uint16_t l_port,
    uint8_t *r_addr,
    uint16_t r_port, 
    int active,
    CALLBACK cb
) {
    TCB *tcb = boar_tcp_find_tcb(boar_tcp, l_port, r_addr, r_port);
    if (tcb) {
        if (active && tcb->state == TCP_LISTEN) {
            tcb->active = active;
            tcb->open_cb = cb;
            tcp_active_open(boar_tcp, tcb);
        } else {
            signal_user(cb, ERRCONNEXI);
        }
    } else {
        tcb = new_tcb(l_addr, l_port, r_addr, r_port);
        tcb->active = active;
        tcb->open_cb = cb;
        boar_tcp_add_tcb(boar_tcp, tcb);
        if (active) {
            tcp_active_open(boar_tcp, tcb);
        } else {
            tcb->state = TCP_LISTEN;
        }
    }
}

static int tqueue_has_room(TCB *tcb) {
    return 1;
}

static void segmentize_and_send(boar_tcp *boar_tcp, TCB *tcb, uint8_t *buf, uint32_t len) {
    if (tcb->snd_wnd == 0) {
        return;
    } else {
        uint8_t *ptr = buf;
        int segl = tcb->snd_wnd;
        int push = 0;
        while (1) {
            if (ptr + segl > buf + len) {
                segl = buf + len - ptr;
                push = 1;
            }
            tcp_seg *seg = segmentize(tcb, ptr, segl, push);
            tcp_send(boar_tcp, tcb, seg);
            ptr += segl;
            if (ptr >= buf + len)
                break;
        }
    }
}

typedef struct {
    uint8_t *data;
    uint32_t len;
} buffer;

buffer *new_buffer(uint8_t *data, uint32_t len) {
    buffer *buffer = malloc(sizeof(*buffer));
    buffer->data = data;
    buffer->len = len;
    return buffer;
}

void boar_tcp_send(
    boar_tcp *boar_tcp,
    uint16_t l_port,
    uint8_t *r_addr,
    uint16_t r_port,
    uint8_t *buf,
    uint8_t len,
    CALLBACK cb
) {
    TCB *tcb = boar_tcp_find_tcb(boar_tcp, l_port, r_addr, r_port);
    if (tcb) {
        switch (tcb->state) {
            case TCP_LISTEN: {
                if (!is_zero_addr(r_addr)) {
                    tcb->active = 1;
                    tcb->iss = get_iss();
                    tcp_send_syn(boar_tcp, tcb);
                    tcb->snd_una = tcb->iss;
                    // tcb->snd_nxt = tcb->iss + 1;
                    tcb->state = TCP_SYN_SENT;
                    if (tqueue_has_room(tcb)) {
                        boar_enqueue(tcb->tqueue, new_buffer(buf, len));
                    } else {
                        signal_user(cb, ERRINSUFRES);
                    }
                } else {
                    signal_user(cb, ERRNOFSOCK);
                }
            }
            break;
            case TCP_SYN_SENT:
            case TCP_SYN_RCVD: {
                if (tqueue_has_room(tcb)) {
                    boar_enqueue(tcb->tqueue, new_buffer(buf, len));
                } else {
                    signal_user(cb, ERRINSUFRES);
                }
            }
            break;
            case TCP_ESTAB:
            case TCP_CLOSE_WAIT: {
                segmentize_and_send(boar_tcp, tcb, buf, len);
            }
            break;
            case TCP_FIN_WAIT_1:
            case TCP_FIN_WAIT_2:
            case TCP_CLOSING:
            case TCP_LAST_ACK:
            case TCP_TIME_WAIT: {
                signal_user(cb, ERRCONNCLOSING);
            }
            break;
        }
    } else {
        signal_user(cb, ERRNOCONN);
    }
}

static int rcvq_has_room(TCB *tcb) {
    return 1;
}

static void rcvq_add(TCB *tcb, receiver *receiver) {
    boar_enqueue(tcb->rcvq, receiver);
}

static void rqueue_get(TCB *tcb, uint8_t *buf, uint32_t len) {
    uint8_t *ptr = buf;
    while (!boar_queue_is_empty(tcb->rqueue)) {
        tcp_seg *seg = boar_queue_peek(tcb->rqueue);
        int l = ptr + seg->len > buf + len ?
            buf + len - ptr : seg->len;
        memcpy(ptr, seg->data, l);
        ptr += seg->len;
        if (ptr >= buf + len) {
            seg->data = seg->data + l;
            seg->len -= l;
            break;
        }
        boar_dequeue(tcb->rqueue);
    }
}

void boar_tcp_receive(
    boar_tcp *boar_tcp,
    uint16_t l_port,
    uint8_t *r_addr,
    uint16_t r_port,
    uint8_t *buf,
    int len,
    CALLBACK cb
) {
    TCB *tcb = boar_tcp_find_tcb(boar_tcp, l_port, r_addr, r_port);
    if (tcb) {
        receiver *rcv = new_receiver(buf, len, cb);
        switch (tcb->state) {
            case TCP_LISTEN:
            case TCP_SYN_SENT:
            case TCP_SYN_RCVD: {
                if (!rcvq_has_room(tcb)) {
                    signal_user(cb, ERRINSUFRES);
                } else {
                    rcvq_add(tcb, rcv);
                }
            }
            break;
            case TCP_ESTAB:
            case TCP_FIN_WAIT_1:
            case TCP_FIN_WAIT_2: {
                // int l = rcv_queued_segs(tcb, buf, len);
                // if (l == len)
                //     signal_user(cb, OK);
                // else if (rcvq_has_room(tcb)) {
                //     receiver *receiver = new_receiver(buf, len, cb);
                //     rcvq_add(tcb, receiver);
                // } else {
                //     signal_user(cb, ERRINSUFRES);
                // }

                if (rqueue_is_empty(tcb)) {
                    if (rcvq_has_room(tcb)) {
                        receiver *rcv = new_receiver(buf, len, cb);
                        rcvq_add(tcb, rcv);
                    } else {
                        signal_user(cb, ERRINSUFRES);
                    }
                } else {
                    rqueue_get(tcb, buf, len);
                    signal_user(cb, OK);
                }
            }
            break;
            case TCP_CLOSE_WAIT: {
                if (rqueue_is_empty(tcb)) {
                    signal_user(cb, ERRCONNCLOSING);
                } else {
                    rqueue_get(tcb, buf, len);
                    signal_user(cb, OK);
                }
            }
            break;
            case TCP_CLOSING:
            case TCP_LAST_ACK:
            case TCP_TIME_WAIT: {
                signal_user(cb, ERRCONNCLOSING);
            }
            break;
        }
    } else {
        signal_user(cb, ERRNOCONN);
    }
}

static int sndq_is_empty(TCB *tcb) {
    return boar_queue_is_empty(tcb->sndq);
}

static void queue_close_call(TCB *tcb, CALLBACK cb) {
    tcb->close_cb = cb;
    tcb->close_queued = 1;
}

void boar_tcp_close(
    boar_tcp *boar_tcp,
    uint16_t l_port,
    uint8_t *r_addr,
    uint16_t r_port,
    CALLBACK cb
) {
    TCB *tcb = boar_tcp_find_tcb(boar_tcp, l_port, r_addr, r_port);
    if (tcb) {
        tcb->close_cb = cb;
        switch (tcb->state) {
            case TCP_LISTEN: {
                notify_snds(tcb, ERRCLOSING);
                boar_tcp_delete_tcb(boar_tcp, tcb);
                signal_user(cb, OK);
            }
            break;
            case TCP_SYN_SENT: {
                notify_snds(tcb, ERRCLOSING);
                boar_tcp_delete_tcb(boar_tcp, tcb);
                signal_user(cb, OK);
            }
            break;
            case TCP_SYN_RCVD: {
                if (sndq_is_empty(tcb)) {
                    tcp_send_fin(boar_tcp, tcb);
                    tcb->state = TCP_FIN_WAIT_1;
                } else {
                    queue_close_call(tcb, cb);
                }
            }
            break;
            case TCP_ESTAB: {
                if (sndq_is_empty(tcb)) {
                    tcp_send_fin(boar_tcp, tcb);
                } else {
                    queue_close_call(tcb, cb);
                }
                tcb->state = TCP_FIN_WAIT_1;
            }
            break;
            case TCP_FIN_WAIT_1:
            case TCP_FIN_WAIT_2: {
                signal_user(cb, ERRCONNCLOSING);
            }
            break;
            case TCP_CLOSE_WAIT: {
                // queue this request until all preceding
                // sends have been segmentized; then send
                // a fin segment, enter closing state
                if (sndq_is_empty(tcb)) {
                    tcp_send_fin(boar_tcp, tcb);
                    boar_tcp_delete_tcb(boar_tcp, tcb);
                    signal_user(cb, OK);
                } else {
                    queue_close_call(tcb, cb);
                }
            }
            break;
            case TCP_CLOSING:
            case TCP_LAST_ACK:
            case TCP_TIME_WAIT: {
                signal_user(cb, ERRCONNCLOSING);
            }
        }
    } else {
        signal_user(cb, ERRNOCONN);
    }
}

void boar_tcp_abort(
    boar_tcp *boar_tcp,
    uint16_t l_port,
    uint8_t *r_addr,
    uint16_t r_port,
    CALLBACK cb
) {
    TCB *tcb = boar_tcp_find_tcb(boar_tcp, l_port, r_addr, r_port);
    if (tcb) {
        switch (tcb->state) {
            case TCP_LISTEN: {
                rst_queued_rcvs(tcb);
                boar_tcp_delete_tcb(boar_tcp, tcb);
                signal_user(cb, OK);
            }
            break;
            case TCP_SYN_SENT: {
                rst_queued_rcvs(tcb);
                rst_queued_snds(tcb);
                boar_tcp_delete_tcb(boar_tcp, tcb);
                signal_user(cb, OK);
            }
            break;
            case TCP_SYN_RCVD:
            case TCP_ESTAB:
            case TCP_FIN_WAIT_1:
            case TCP_FIN_WAIT_2:
            case TCP_CLOSE_WAIT: {
                tcp_send_rst(boar_tcp, tcb);
                rst_queued_snds(tcb);
                rst_queued_rcvs(tcb);

                tqueue_flush(boar_tcp, tcb);
                rtqueue_flush(boar_tcp, tcb);

                boar_tcp_delete_tcb(boar_tcp, tcb);
                signal_user(cb, OK);
            }
            break;
            case TCP_CLOSING:
            case TCP_LAST_ACK:
            case TCP_TIME_WAIT: {
                signal_user(cb, OK);
                boar_tcp_delete_tcb(boar_tcp, tcb);
                signal_user(cb, OK);
            }
            break;
        }
    } else {
        signal_user(cb, ERRNOCONN);
    }
}

void boar_tcp_status(
    boar_tcp *boar_tcp,
    uint16_t l_port,
    uint8_t *r_addr,
    uint16_t r_port
) {
    TCB *tcb = boar_tcp_find_tcb(boar_tcp, l_port, r_addr, r_port);
    if (tcb) {
        switch (tcb->state) {
            case TCP_LISTEN: {
            }
            break;
            case TCP_SYN_SENT: {
            }
            break;
            case TCP_SYN_RCVD: {
            }
            break;
            default:
            break;
        }
    } else {
    }
}

static void tcp_close(boar_tcp *boar_tcp, TCB *tcb) {
    sndq_flush(boar_tcp, tcb);
    tcp_send_fin(boar_tcp, tcb);
    tcb->state = TCP_FIN_WAIT_1;
}

static uint8_t header_flags(struct tcp_header *tcp_header) {
    uint8_t flags = 0;
    if (tcp_header->flags.ack)
        flags |= ACK;
    if (tcp_header->flags.syn)
        flags |= SYN;
    if (tcp_header->flags.reset)
        flags |= RST;
    if (tcp_header->flags.fin)
        flags |= FIN;
    return flags;
}

static tcp_seg *make_tcp_seg(struct tcp_header *tcp_header,
        uint8_t *data, uint32_t data_len) {
    uint8_t flags = header_flags(tcp_header);
    return new_tcp_seg(tcp_header->seq_num, tcp_header->ack_num,
        flags, data, data_len);
}

// static void rqueue_add(TCB *tcb, tcp_seg *seg) {
//     boar_enqueue(tcb->rqueue, seg);
// }

void boar_tcp_seg_arv(
    boar_tcp *boar_tcp,
    uint8_t *l_addr,
    uint8_t *r_addr,
    uint8_t *buf,
    uint8_t len
) {
    struct tcp_header *tcp_header = unmarshal_tcp_header(buf);
    int header_len = tcp_header->header_length * 4;
    uint8_t *data = buf + header_len;
    int data_len = len - header_len;
    TCB *tcb = boar_tcp_find_tcb(boar_tcp, tcp_header->dst_port, r_addr,
        tcp_header->src_port);

    tcp_seg *seg = make_tcp_seg(tcp_header, data, data_len);

    if (tcb) {
        switch (tcb->state) {
            case TCP_LISTEN: {
                if (tcp_header->flags.reset) {
                    /* ignore and return */
                    return;
                } else if (tcp_header->flags.ack) {
                    tcp_rst_seg(boar_tcp, tcb, seg);
                    return;
                } else if (tcp_header->flags.syn) {
                    tcb->rcv_nxt = tcp_header->seq_num + 1;
                    tcb->irs = tcp_header->seq_num;
                    tcb->iss = get_iss();
                    tcp_send_syn_ack(boar_tcp, tcb);
                    tcb->snd_nxt = tcb->iss + 1;
                    tcb->snd_una = tcb->iss;
                    tcb->state = TCP_SYN_RCVD;

                    tcb->r_port = tcp_header->src_port;
                    memcpy(tcb->r_addr, r_addr, 4);

                    fill_fields(tcb, r_addr, tcp_header->src_port);
                } else {
                    /* ignore and return */
                    return;
                }
            }
            break;
            case TCP_SYN_SENT: {
                if (tcp_header->flags.ack) {
                    if (tcp_header->ack_num <= tcb->iss ||
                            tcp_header->ack_num > tcb->snd_nxt) {
                        if (!tcp_header->flags.reset) {
                            tcp_rst_seg(boar_tcp, tcb, seg);
                        }
                        return;
                    }
                }

                if (tcp_header->flags.reset) {
                    boar_tcp_delete_tcb(boar_tcp, tcb);
                    // signal_user("error: connection reset");
                    notify_opener(tcb, ERRCONNRST);
                    return;
                }

                if (tcp_header->flags.syn) {
                    tcb->rcv_nxt = tcp_header->seq_num + 1;
                    tcb->irs = tcp_header->seq_num;

                    if (tcp_header->flags.ack) {
                        rcv_ack(tcb, tcp_header->ack_num);
                    }

                    if (tcb->snd_una > tcb->iss) {  // syn acked
                        /* data or controls which were queued for
                           transmission may be included */
                        tcp_send_ack(boar_tcp, tcb);

                        tqueue_flush(boar_tcp, tcb);

                        tcb->state = TCP_ESTAB;
                        notify_opener(tcb, OK);

                        if (tcb->close_queued) {
                            tcp_close(boar_tcp, tcb);
                            return;
                        }
                    } else {
                        tcp_send_syn_ack(boar_tcp, tcb);
                        tcb->state = TCP_SYN_RCVD;
                    }
                } else {
                    return;
                }
            }
            break;
            default: {
                int acceptable = 0;
                if (seg->len == 0 && tcb->rcv_wnd == 0) {
                    if (seg->seq == tcb->rcv_nxt)
                        acceptable = 1;
                } else if (seg->len == 0 && tcb->rcv_wnd > 0) {
                    if (seg->seq >= tcb->rcv_nxt &&
                            seg->seq < tcb->rcv_nxt + tcb->rcv_wnd)
                        acceptable = 1;
                } else if (seg->len > 0 && tcb->rcv_wnd > 0) {
                    if ((seg->seq >= tcb->rcv_nxt &&
                            seg->seq < tcb->rcv_nxt + tcb->rcv_wnd) ||
                            (seg->seq + seg->len - 1 >= tcb->rcv_nxt &&
                            seg->seq + seg->len - 1 < tcb->rcv_nxt + tcb->rcv_wnd))
                        acceptable = 1;
                }

                if (!acceptable) {
                    if (!(seg->flags & RST))
                        tcp_send_ack(boar_tcp, tcb);
                    /* drop segment and return */
                    free_tcp_seg(seg);
                    return;
                } else {
                    if (seg->flags & RST) {
                        switch (tcb->state) {
                            case TCP_SYN_RCVD: {
                                rtqueue_remove_all(tcb);
                                if (!tcb->active) {
                                    tcb->state = TCP_LISTEN;
                                } else {
                                    notify_opener(tcb, ERRCONNREFUSED);
                                    boar_tcp_delete_tcb(boar_tcp, tcb);
                                    return;
                                }
                            }
                            break;
                            case TCP_ESTAB:
                            case TCP_FIN_WAIT_1:
                            case TCP_FIN_WAIT_2:
                            case TCP_CLOSE_WAIT: {
                                flush(boar_tcp, tcb);
                                notify_users(tcb, ERRCONNRST);
                                boar_tcp_delete_tcb(boar_tcp, tcb);
                                return;
                            }
                            break;
                            case TCP_CLOSING:
                            case TCP_LAST_ACK:
                            case TCP_TIME_WAIT: {
                                boar_tcp_delete_tcb(boar_tcp, tcb);
                                return;
                            }
                            break;
                            default:
                            break;
                        }
                    }

                    if (seg->flags & SYN) {
                        tcp_rst_seg(boar_tcp, tcb, seg);
                        flush(boar_tcp, tcb);
                        /* any outstanding receives and
                           send should receive reset responses,
                           the user should also receive an unsolicited
                           general connection reset signal
                          */
                        notify_users(tcb, ERRCONNRST);
                        boar_tcp_delete_tcb(boar_tcp, tcb);
                        return;
                    }

                    if (!(seg->flags & ACK)) {
                        return;
                    } else {
                        switch (tcb->state) {
                            case TCP_SYN_RCVD: {
                                if (seg->ack >= tcb->snd_una &&
                                        seg->ack <= tcb->snd_nxt) {
                                    tcb->snd_una = seg->ack;
                                    tqueue_flush(boar_tcp, tcb);

                                    tcb->state = TCP_ESTAB;
                                    notify_opener(tcb, OK);

                                    if (tcb->close_queued) {
                                        tcp_close(boar_tcp, tcb);
                                        return;
                                    }
                                } else {
                                    tcp_rst_seg(boar_tcp, tcb, seg);
                                    return;
                                }
                            }
                            break;
                            case TCP_ESTAB:
                            case TCP_FIN_WAIT_1:
                            case TCP_FIN_WAIT_2:
                            case TCP_CLOSE_WAIT:
                            case TCP_CLOSING: {
                                if (seg->ack > tcb->snd_una &&
                                        seg->ack <= tcb->snd_nxt) {
                                    tcb->snd_una = seg->ack;
                                    rtqueue_remove_and_update_rtto(tcb);

                                    if (tcb->snd_wl1 < seg->seq ||
                                            (tcb->snd_wl1 == seg->seq &&
                                             tcb->snd_wl2 <= seg->ack) ||
                                            (tcb->snd_wl1 == 0 && tcb->snd_wl2 == 0)) {
                                        tcb->snd_wnd = seg->wnd;
                                        tcb->snd_wl1 = seg->seq;
                                        tcb->snd_wl2 = seg->ack;
                                    }

                                    if (tcb->close_queued)
                                        signal_user(tcb->close_cb, OK);
                                } else if (seg->ack <= tcb->snd_una) {
                                    /* ignore */
                                } else if (seg->ack > tcb->snd_nxt) {
                                    tcp_ack_seg(boar_tcp, tcb, seg);
                                }

                                if (tcb->state == TCP_FIN_WAIT_1) {
                                    tcb->state = TCP_FIN_WAIT_2;
                                } else if (tcb->state == TCP_FIN_WAIT_2) {
                                    if (fin_acked(tcb)) {
                                        if (rtqueue_is_empty(tcb))
                                            notify_closer(tcb, OK);
                                    }
                                }
                            }
                            break;
                            case TCP_LAST_ACK: {
                                if (fin_acked(tcb)) {
                                    boar_tcp_delete_tcb(boar_tcp, tcb);
                                    return;
                                }
                            }
                            break;
                            case TCP_TIME_WAIT: {
                                tcp_ack_seg(boar_tcp, tcb, seg);
                                start_time_wait_timer(tcb);
                            }
                            break;
                            default:
                            break;
                        }
                    }
                }

                switch (tcb->state) {
                    case TCP_ESTAB:
                    case TCP_FIN_WAIT_1:
                    case TCP_FIN_WAIT_2: {
                        if (seg->len > 0) {
                            // int l;
                            // if (seg->len > len)
                            //     l = len;
                            // else
                            //     l = seg->len;
                            // memcpy(buf, seg->data, l);

                            // if (seg->len > l) {
                            //     seg->len -= l;
                            //     uint8_t *data = malloc(seg->len);
                            //     memcpy(data, seg->data + len, seg->len);
                            //     free(seg->data);
                            //     seg->data = data;
                            //     rqueue_add(tcb, seg);
                            // }

                            tcp_send_ack(boar_tcp, tcb);

                            // if ((seg->flags & PUSH) && len == seg->len)
                            //     inform_user(PUSH);
                            // return;
                        }
                    }
                    break;
                    default:
                    break;
                }

                if (seg->flags & FIN) {
                    switch (tcb->state) {
                        case TCP_SYN_RCVD:
                        case TCP_ESTAB: {
                            tcb->state = TCP_CLOSE_WAIT;
                        }
                        break;
                        case TCP_FIN_WAIT_1: {
                            if (fin_acked(tcb)) {
                                notify_closer(tcb, OK);

                                tcb->state = TCP_TIME_WAIT;
                                turn_off_timers(tcb);
                                start_time_wait_timer(tcb);
                            } else {
                                tcb->state = TCP_CLOSING;
                            }
                        }
                        break;
                        case TCP_FIN_WAIT_2: {
                            notify_closer(tcb, OK);

                            tcb->state = TCP_TIME_WAIT;
                            turn_off_timers(tcb);
                            start_time_wait_timer(tcb);
                        }
                        break;
                        case TCP_CLOSE_WAIT: {
                            /* remain in close-wait state */
                        }
                        break;
                        case TCP_LAST_ACK: {
                            /* remain in last-ack state */
                        }
                        break;
                        case TCP_TIME_WAIT: {
                            start_time_wait_timer(tcb);
                        }
                        default:
                        break;
                    }
                }
            }
        }
    } else {
        if (!tcp_header->flags.reset) {
            uint8_t l_addr[] = { 0, 0, 0, 0 };
            TCB *tcb = new_tcb(l_addr,
                               tcp_header->dst_port,
                               r_addr,
                               tcp_header->src_port);
            tcp_close_closed(boar_tcp, tcb, seg);
        }
    }
}

// static void flush_all_queues(boar_tcp *boar_tcp, TCB *tcb) {
//     rtqueue_flush(boar_tcp, tcb);
//     tqueue_flush(boar_tcp, tcb);
// }

// static void boar_tcp_user_timeout(
//     boar_tcp *boar_tcp,
//     TCB *tcb
// ) {
//     flush_all_queues(boar_tcp, tcb);
//     boar_tcp_delete_tcb(boar_tcp, tcb);
//     // signal_user("error: connection aborted due to user timeout");
//     notify_users(tcb, ERRCONNUTIMEOUT);
// }

static void boar_tcp_retrans_timeout(
    boar_tcp *boar_tcp,
    TCB *tcb
) {
    tcp_seg *seg = boar_dequeue(tcb->rtqueue);
    tcp_send(boar_tcp, tcb, seg);
    start_retrans_timer(tcb);
}

static void boar_tcp_time_wait_timeout(
    boar_tcp *boar_tcp,
    TCB *tcb
) {
    boar_tcp_delete_tcb(boar_tcp, tcb);
}

void boar_tcp_check_rtto(boar_tcp *boar_tcp) {
    boar_list_node *ptr;
    for (ptr = boar_tcp->tcb_list->head; ptr; ptr = ptr->next) {
        TCB *tcb = ptr->value;
        if (tcb_rtto(tcb)) {
            boar_tcp_retrans_timeout(boar_tcp, tcb);
        }
    }
}

void boar_tcp_check_twto(boar_tcp *boar_tcp) {
    boar_list_node *ptr;
    for (ptr = boar_tcp->tcb_list->head; ptr; ptr = ptr->next) {
        TCB *tcb = ptr->value;
        if (tcb_twto(tcb))
            boar_tcp_time_wait_timeout(boar_tcp, tcb);
    }
}

void boar_tcp_check_uto(boar_tcp *boar_tcp) {
    // tbd
}

static void tcp_rst_seg(boar_tcp *boar_tcp, TCB *tcb, tcp_seg *seg) {
    tcp_seg *rseg = new_tcp_seg(seg->ack, 0, RST, 0, 0);
    tcp_send(boar_tcp, tcb, rseg);
}

static uint32_t get_iss() {
    struct timeval tv;
    gettimeofday(&tv, 0);

    return tv.tv_usec / 1000 + tv.tv_sec * 1000;
}

static void fill_fields(TCB *tcb, uint8_t *r_addr, uint16_t r_port) {
    memcpy(tcb->r_addr, r_addr, 4);
    tcb->r_port = r_port;
}

static void rcv_ack(TCB *tcb, uint32_t ack) {
    tcb->snd_una = ack;
    rtqueue_remove_and_update_rtto(tcb);
}

static void notify_users(TCB *tcb, tcp_error err) {
    // boar_queue_node *ptr;
    // for (ptr = tcb->rcvq->head; ptr; ptr = ptr->next) {
    //     receiver *rcv = ptr->value;
    //     signal_user(rcv->callback, err);
    // }
    // for (ptr = tcb->sndq->head; ptr; ptr = ptr->next) {
    //     sender *snd = ptr->value;
    //     signal_user(snd->callback, err);
    // }
    notify_rcvs(tcb, err);
    notify_snds(tcb, err);
}

static int rtqueue_is_empty(TCB *tcb) {
    return boar_queue_is_empty(tcb->rtqueue);
}

static int fin_acked(TCB *tcb) {
    if (rtqueue_is_empty(tcb))
        return 1;
    return 0;
}

static void rtqueue_flush(boar_tcp *boar_tcp, TCB *tcb) {
    boar_queue_node *ptr;
    for (ptr = tcb->rtqueue->head; ptr; ptr = ptr->next) {
        tcp_seg *seg = ptr->value;
        tcp_send(boar_tcp, tcb, seg);
    }
}

static void sndq_flush(boar_tcp *boar_tcp, TCB *tcb) {
    // tbd
}

static void flush(boar_tcp *boar_tcp, TCB *tcb) {
    rtqueue_flush(boar_tcp, tcb);
    sndq_flush(boar_tcp, tcb);
}

static int get_curtime() {
    struct  timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int tcb_rtto(TCB *tcb) {
    if (!tcb->rtt_on)
        return 0;
    int elapsed = get_curtime() - tcb->rtt_start;
    return elapsed >= tcb->rtto;
}

static int tcb_twto(TCB *tcb) {
    if (!tcb->twt_on)
        return 0;
    int elapsed = get_curtime() - tcb->twt_start;
    return elapsed >= tcb->twto;
}

static void start_retrans_timer(TCB *tcb) {
    tcb->twt_on = 1;
    tcb->rtt_start = get_curtime();
}

static void start_time_wait_timer(TCB *tcb) {
    tcb->twt_on = 1;
    tcb->twt_start = get_curtime();
}

static void turn_off_timers(TCB *tcb) {
    tcb->rtt_on = 0;
    tcb->twt_on = 0;
}

static tcp_seg *new_tcp_seg(uint32_t seq, uint32_t ack, uint8_t flags,
        uint8_t *data, uint32_t len) {
    tcp_seg *seg = malloc(sizeof(*seg));
    seg->seq = seq;
    seg->ack = ack;
    seg->flags = flags;
    seg->data = data;
    seg->len = len;
    seg->wnd = 0;

    return seg;
}

static void free_tcp_seg(tcp_seg *seg) {
    // free(seg->data);
    free(seg);
}

// static tcp_seg *new_tcp_seg2(uint8_t *data, uint32_t len) {
//     tcp_seg *seg = malloc(sizeof(*seg));
//     seg->data = data;
//     seg->len = len;

//     return seg;
// }

static receiver *new_receiver(uint8_t *buf, int len, CALLBACK cb) {
    receiver *receiver = malloc(sizeof(*receiver));
    receiver->buf = buf;
    receiver->len = len;
    receiver->callback = cb;

    return receiver;
}

// static void tqueue_add(TCB *tcb, tcp_seg *seg) {
//     boar_enqueue(tcb->tqueue, seg);
// }

static tcp_seg *segmentize(TCB *tcb, uint8_t *ptr, int len, int push) {
    uint8_t *data = malloc(len);
    memcpy(data, ptr, len);

    uint8_t flags = ACK;
    if (push)
        flags |= PUSH;
    tcp_seg *seg = new_tcp_seg(tcb->snd_nxt, tcb->rcv_nxt, flags, data, len);
    // tqueue_add(tcb, seg);
    return seg;
}

static int rqueue_is_empty(TCB *tcb) {
    return boar_queue_is_empty(tcb->rqueue);
}

// static int tqueue_is_empty(TCB *tcb) {
//     return boar_queue_is_empty(tcb->tqueue);
// }

static int rcvq_is_empty(TCB *tcb) {
    return boar_queue_is_empty(tcb->rcvq);
}

static receiver *rcvq_rm(TCB *tcb) {
    return boar_dequeue(tcb->rcvq);
}

static sender *sndq_rm(TCB *tcb) {
    return boar_dequeue(tcb->sndq);
}

static void notify_rcvs(TCB *tcb, tcp_error err) {
    while (!rcvq_is_empty(tcb)) {
        receiver *receiver = rcvq_rm(tcb);
        signal_user(receiver->callback, err);
    }
}

static void notify_snds(TCB *tcb, tcp_error err) {
    while (!sndq_is_empty(tcb)) {
        sender *sender = sndq_rm(tcb);
        signal_user(sender->callback, err);
    }
}

static void update_rtto(TCB *tcb, int rtt) {
    float alpha = 0.8;
    // float beta = 1.5;

    tcb->srtt = alpha * tcb->srtt + (1 - alpha) * rtt;
    tcb->rtto = 1;
    if (tcb->rtto < tcb->srtt)
        tcb->rtto = tcb->srtt;
    if (tcb->rtto > 60)
        tcb->rtto = 60;
}

static void rst_queued_rcvs(TCB *tcb) {
    while (!boar_queue_is_empty(tcb->rcvq)) {
        CALLBACK rcv_callback = boar_dequeue(tcb->rcvq);
        signal_user(rcv_callback, ERRCONNRST);
    }
}

static void rst_queued_snds(TCB *tcb) {
    while (!boar_queue_is_empty(tcb->sndq)) {
        CALLBACK snd_callback = boar_dequeue(tcb->sndq);
        signal_user(snd_callback, ERRCONNRST);
    }
}

// static void rtqueue_remove(TCB *tcb, uint32_t una) {
//     while (!boar_queue_is_empty(tcb->rtqueue)) {
//         tcp_seg *seg = boar_queue_peek(tcb->rtqueue);
//         if (seg->seq < una)
//             boar_dequeue(tcb->rtqueue);
//         else
//             break;
//     }
// }

static void rtqueue_remove_and_update_rtto(TCB *tcb) {
    while (!boar_queue_is_empty(tcb->rtqueue)) {
        tcp_seg *seg = boar_queue_peek(tcb->rtqueue);
        if (seg->seq < tcb->snd_una) {
            int rtt = get_curtime() - seg->snd_time;
            update_rtto(tcb, rtt);

            boar_dequeue(tcb->rtqueue);
        }
        else
            break;
    }
}

static void rtqueue_remove_all(TCB *tcb) {
    while (!boar_queue_is_empty(tcb->rtqueue)) {
        boar_dequeue(tcb->rtqueue);
    }
}

static inline int is_zero_addr(uint8_t *addr) {
    for (int i = 0; i < 4; i++)
        if (addr[i])
            return 0;
    return 1;
}

static TCB *boar_tcp_find_tcb(boar_tcp *boar_tcp, uint16_t l_port,
        uint8_t *r_addr, uint16_t r_port) {
    if (!boar_tcp->tcb_list->head)
        return 0;

    boar_list_node *ptr = boar_tcp->tcb_list->head;
    for ( ; ptr; ptr = ptr->next) {
        TCB *tcb = ptr->value;

        if (tcb->l_port == l_port && !memcmp(tcb->r_addr, r_addr, 4)
                && tcb->r_port == r_port) {
            return tcb;
        } else if (tcb->l_port == l_port && is_zero_addr(tcb->r_addr)
                && tcb->r_port == 0) {
            return tcb;
        } else {
            return 0;
        }
    }

    return 0;
}

static inline void boar_tcp_delete_tcb(boar_tcp *boar_tcp, TCB *tcb) {
    boar_list_remove(boar_tcp->tcb_list, tcb);
    free_tcb(tcb);
}

static inline void boar_tcp_add_tcb(boar_tcp *boar_tcp, TCB *tcb) {
    boar_list_push(boar_tcp->tcb_list, tcb);
}

// static inline void boar_tcp_connect(boar_tcp *boar_tcp, TCB *tcb) {
//     struct tcp_header *tcp_header = new_tcp_header(tcb);
// }

#define DEFAULT_RECEIVE_WINDOW_SIZE 512
#define DEFAULT_SEND_WINDOW_SIZE 512

static TCB *new_tcb(uint8_t *l_addr, uint16_t l_port, uint8_t *r_addr, uint16_t r_port) {
    TCB *tcb = malloc(sizeof(*tcb));
    memcpy(tcb->l_addr, l_addr, 4);
    tcb->l_port = l_port;
    memcpy(tcb->r_addr, r_addr, 4);
    tcb->r_port = r_port;

    tcb->rtqueue = new_boar_queue();

    tcb->tqueue = new_boar_queue();

    tcb->rqueue = new_boar_queue();

    tcb->sndq = new_boar_queue();
    tcb->rcvq = new_boar_queue();

    tcb->rcv_wnd = DEFAULT_RECEIVE_WINDOW_SIZE;

    tcb->close_queued = 0;

    tcb->snd_wnd = DEFAULT_SEND_WINDOW_SIZE;
    tcb->snd_wl1 = 0;
    tcb->snd_wl2 = 0;

    return tcb;
}

static void free_tcb(TCB *tcb) {
    // free_boar_queue(tcb->rtqueue);
    free(tcb);
}

#define DEFAULT_WINDOW_SIZE 512

static struct tcp_header *new_tcp_header(TCB *tcb) {
    struct tcp_header *tcp_header = malloc(sizeof(*tcp_header));
    tcp_header->header_length = TCP_HEADER_SIZE / 4;
    tcp_header->flags.ack = 0;
    tcp_header->flags.syn = 0;
    tcp_header->flags.reset = 0;
    tcp_header->flags.push = 0;
    tcp_header->flags.fin = 0;
    tcp_header->flags.urgent = 0;

    tcp_header->src_port = tcb->l_port;
    tcp_header->dst_port = tcb->r_port;

    tcp_header->window_size = DEFAULT_WINDOW_SIZE;

    tcp_header->checksum = 0;

    return tcp_header;
}

static void tcp_send_syn_ack(boar_tcp *boar_tcp, TCB *tcb) {
    tcp_send_ctl(boar_tcp, tcb, tcb->iss, tcb->rcv_nxt, SYN | ACK);
}

static void tcp_send_syn(boar_tcp *boar_tcp, TCB *tcb) {
    tcp_send_ctl(boar_tcp, tcb, tcb->iss, 0, SYN);
}

static void tcp_send_rst(boar_tcp *boar_tcp, TCB *tcb) {
    tcp_send_ctl(boar_tcp, tcb, tcb->snd_nxt, 0, RST);
}

static void tcp_send_fin(boar_tcp *boar_tcp, TCB *tcb) {
    tcp_send_ctl(boar_tcp, tcb, tcb->snd_nxt, tcb->rcv_nxt, FIN | ACK);
    tcb->state = TCP_FIN_WAIT_1;
}

static void tcp_send_ack(boar_tcp *boar_tcp, TCB *tcb) {
    tcp_send_ctl(boar_tcp, tcb, tcb->snd_nxt, tcb->rcv_nxt, ACK);
}

static void tcp_ack_seg(boar_tcp *boar_tcp, TCB *tcb, tcp_seg *seg) {
    tcp_send_ctl(boar_tcp, tcb, seg->seq, 0, ACK);
}

static void tcp_send_ctl(boar_tcp *boar_tcp, TCB *tcb,
        uint32_t seq_num, uint32_t ack_num, uint8_t flags) {
    tcp_seg *seg = new_tcp_seg(seq_num, ack_num, flags, 0, 0);
    tcp_send(boar_tcp, tcb, seg);
}

static void tcp_close_closed(boar_tcp *boar_tcp, TCB *tcb, tcp_seg *seg) {
    uint32_t seq, ack;
    uint8_t flags = RST;
    if (seg->flags & ACK) {
        seq = seg->ack;
        ack = 0;
    } else {
        seq = 0;
        ack = seg->seq + seg->len;
        flags |= ACK;
    }
    tcp_send_ctl(boar_tcp, tcb, seq, ack, flags);
}

static void tcp_active_open(boar_tcp *boar_tcp, TCB *tcb) {
    tcb->iss = get_iss();
    tcb->snd_una = tcb->iss;
    // tcb->snd_nxt = tcb->iss + 1;
    tcb->snd_nxt = tcb->iss;
    tcp_send_syn(boar_tcp, tcb);
    tcb->state = TCP_SYN_SENT;
}

static void rtqueue_add(TCB *tcb, tcp_seg *seg) {
    boar_enqueue(tcb->rtqueue, seg);
}

static void set_header_flags(struct tcp_header *tcp_header, uint8_t flags) {
    if (flags & ACK)
        tcp_header->flags.ack = 1;
    if (flags & SYN)
        tcp_header->flags.syn = 1;
    if (flags & RST)
        tcp_header->flags.reset = 1;
    if (flags & FIN)
        tcp_header->flags.fin = 1;
    if (flags & PUSH)
        tcp_header->flags.push = 1;
}

static void tcp_send(boar_tcp *boar_tcp, TCB *tcb, tcp_seg *seg) {
    struct tcp_header *tcp_header = new_tcp_header(tcb);
    tcp_header->seq_num = seg->seq;
    tcp_header->ack_num = seg->ack;
    set_header_flags(tcp_header, seg->flags);

    tcp_header->checksum = tcp_checksum(tcp_header, 0, 0,
        tcb->l_addr, tcb->r_addr);
    uint8_t *header_buf = marshal_tcp_header(tcp_header);

    uint8_t *buf;
    int buf_len;
    if (seg->len > 0) {
        buf = realloc(header_buf, TCP_HEADER_SIZE + seg->len);
        memcpy(buf + TCP_HEADER_SIZE, seg->data, seg->len);
        buf_len = TCP_HEADER_SIZE + seg->len;
    } else {
        buf = header_buf;
        buf_len = TCP_HEADER_SIZE;
    }
    tcp_send_buf(boar_tcp, tcb->r_addr, buf, buf_len);

    tcb->snd_nxt += seg->len;
    if (seg->flags & SYN)
        tcb->snd_nxt++;
    if (seg->flags & FIN)
        tcb->snd_nxt++;
    seg->snd_time = get_curtime();
    rtqueue_add(tcb, seg);
}

static void tcp_send_buf(boar_tcp *boar_tcp, uint8_t *r_addr, uint8_t *buf, int buf_len) {
    boar_tcp->send(boar_tcp->stack, r_addr, buf, buf_len);
}

static void signal_user(CALLBACK cb, tcp_error err) {
    cb(err);
}

static void notify_opener(TCB *tcb, tcp_error err) {
    signal_user(tcb->open_cb, err);
}

static void notify_closer(TCB *tcb, tcp_error err) {
    signal_user(tcb->close_cb, err);
}

static void tqueue_flush(boar_tcp *boar_tcp, TCB *tcb) {
    boar_queue_node *ptr;
    for (ptr = tcb->tqueue->head; ptr; ptr = ptr->next) {
        buffer *buffer = ptr->value;
        segmentize_and_send(boar_tcp, tcb, buffer->data, buffer->len);
    }
}
