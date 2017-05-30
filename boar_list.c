#include "boar_list.h"
#include <stdlib.h>

boar_list *new_boar_list() {
    boar_list *list = malloc(sizeof(*list));
    list->head = 0;
    list->len = 0;

    return list;
}

static boar_list_node *new_boar_list_node(void *value) {
    boar_list_node *node = malloc(sizeof(*node));
    node->value = value;
    node->next = 0;

    return node;
}

static void free_boar_list_node(boar_list_node *node) {
    free(node->value);
    free(node);
}

void boar_list_push(boar_list *list, void *value) {
    boar_list_node *new_head = new_boar_list_node(value);
    new_head->next = list->head;
    list->head = new_head;
    list->len++;
}

void boar_list_remove(boar_list *list, void *value) {
    if (!list->head)
        return;

    if (!list->head->next) {
        if (list->head->value == value) {
            free(list->head);
            list->head = 0;

            list->len--;
        }
        return;
    }

    boar_list_node *ptr = list->head;
    for ( ; ptr->next; ptr = ptr->next) {
        if (ptr->next->value == value) {
            ptr->next = ptr->next->next;
            free_boar_list_node(ptr->next);

            list->len--;
        }
    }
}

int boar_list_len(boar_list *list) {
    return list->len;
}
