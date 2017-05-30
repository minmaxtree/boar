#include "../boar.h"
#include "../stack.h"
#include <string.h>

#define TEST_FUNC void

boar_tcp *br_tcp;

uint8_t l_addr[] = { 192, 168, 10, 100 };
uint16_t l_port = 9999;
uint8_t r_addr[] = { 192, 168, 10, 1 };
uint16_t r_port = 8888;

void close_cb(tcp_error msg) {
    printf("boar_tcp_close returns: %d\n", msg);
}

void send_cb(tcp_error msg) {
    printf("boar_tcp_send returns: %d\n", msg);
    boar_tcp_close(br_tcp, l_port, r_addr, r_port, close_cb);
}

void open_cb(tcp_error msg) {
    printf("boar_tcp_open returns: %d\n", msg);

    char buf[] = "hello";
    int len = strlen(buf);
    boar_tcp_send(br_tcp, l_port, r_addr, r_port, (uint8_t *)buf, len, send_cb);
}

void *user(void *arg) {
    br_tcp = arg;
    int active = 1;
    sleep(10);
    boar_tcp_open(br_tcp, l_addr, l_port, r_addr, r_port, active, open_cb);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <cfg_file>\n", argv[0]);
        exit(-1);
    }
    char *cfg_file = argv[1];
    printf("use config file: %s\n", cfg_file);

    uint8_t gateway[] = { 192, 168, 10, 1 };
    boar_stack *stack = new_boar_stack(gateway, cfg_file);

    // pthread_t user_thread;
    // pthread_create(&user_thread, 0, user, stack->tcp);

    boar_stack_start(stack);
    pthread_exit(0);
}
