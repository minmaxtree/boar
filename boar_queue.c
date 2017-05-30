#include "boar_queue.h"
#include <stdlib.h>

boar_queue *new_boar_queue() {
    boar_queue *queue = malloc(sizeof(*queue));
    queue->head = 0;
    queue->tail = 0;

    return queue;
}

static boar_queue_node *new_boar_queue_node(void *value) {
    boar_queue_node *node = malloc(sizeof(*node));
    node->value = value;
    node->prev = 0;
    node->next = 0;

    return node;
}

void boar_enqueue(boar_queue *queue, void *value) {
    boar_queue_node *new_head = new_boar_queue_node(value);
    if (!queue->head) {
        queue->head = new_head;
        queue->tail = new_head;
    } else {
        new_head->next = queue->head;
        queue->head->prev = new_head;
        queue->head = new_head;
    }
}

void *boar_dequeue(boar_queue *queue) {
    if (!queue->head)
        return 0;

    void *ret = queue->head->value;
    queue->head = queue->head->next;
    return ret;
}

// void *boar_dequeue(boar_queue *queue) {
//     if (!queue->tail)
//         return 0;

//     void *ret = queue->tail->value;
//     if (queue->tail->prev) {
//         queue->tail = queue->tail->prev;
//         free(queue->tail->next);
//         queue->tail->next = 0;
//     } else {
//         free(queue->tail);
//         queue->head = 0;
//         queue->tail = 0;
//     }

//     return ret;
// }

int boar_queue_is_empty(boar_queue *queue) {
    if (queue->tail)
        return 0;
    return 1;
}

void *boar_queue_peek(boar_queue *queue) {
    return queue->tail->value;
}
