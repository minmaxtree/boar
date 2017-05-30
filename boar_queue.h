#ifndef __BOAR_QUEUE_H__
#define __BOAR_QUEUE_H__

typedef struct boar_queue_node boar_queue_node;

typedef struct boar_queue {
    boar_queue_node *head;
    boar_queue_node *tail;
} boar_queue;

struct boar_queue_node {
    void *value;
    boar_queue_node *next;
    boar_queue_node *prev;
};

boar_queue *new_boar_queue();
void boar_enqueue(boar_queue *queue, void *value);
void *boar_dequeue(boar_queue *queue);
int boar_queue_is_empty(boar_queue *queue);
void *boar_queue_peek(boar_queue *queue);

#endif
