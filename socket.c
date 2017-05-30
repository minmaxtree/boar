#include "socket.h"
#include "stack.h"

// int br_tcp_socket() {
//     struct tcp_socket *tcp_socket = malloc(sizeof(*tcp_socket));
//     tcp_socket->state = TS_CLOSED;

//     stack->tcp_socks[stack->tcp_sock_cnt] = tcp_socket;
//     return stack->tcp_sock_cnt++;
// }

// void bind_tcp(int socknum, uint16_t port) {
//     stack->tcp_socks[socknum]->l_port = port;
// }

// void br_listen(int socknum) {
//     stack->tcp_socks[socknum]->state = TS_LISTEN;
// }

// void br_connect(int socknum) {
//     stack->tcp_socks[socknum]->state = TS_OPEN;
// }

// ssize_t send_tcp(int socknum, char *buf, size_t len) {
//     struct tcp_socket *tcp_socket = stack->tcp_socks[socknum];
//     if (tcp_socket->state != TS_ESTAB)
//         return -1;
//     memcpy(boar_input_buf, buf, len);
//     tcp_socket->input_comes = true;
//     return 0;
// }

// int br_udp_socket(enum socket_type st) {
//     struct udp_socket *udp_socket = malloc(sizeof(*udp_socket));
//     udp_socket->output_comes = false;
//     udp_socket->input_comes = false;

//     stack->udp_socks[stack->udp_sock_cnt] = udp_socket;
//     return stack->udp_sock_cnt++;
// }

// void send_udp(int socknum, char *buf, size_t len, uint8_t *dst_ip_addr, uint16_t dst_port) {
//     memcpy(boar_input_buf, buf, len);
//     boar_input_len = len;

//     memcpy(stack->udp_socks[socknum]->r_ip_addr, dst_ip_addr, 4);
//     stack->udp_socks[socknum]->r_port = dst_port;
//     stack->udp_socks[socknum]->input_comes = true;
// }

// void bind_udp(int socknum, uint16_t port) {
//     stack->udp_socks[socknum]->l_port = port;
// }

// ssize_t recv_udp(int socknum, char *buf, size_t len) {
//     struct udp_socket *udp_socket = stack->udp_socks[socknum];
//     while (!udp_socket->output_comes)
//         ;

//     if (boar_output_len < len)
//         len = boar_output_len;
//     memcpy(buf, boar_output_buf, len);

//     udp_socket->output_comes = false;
//     return len;
// }
