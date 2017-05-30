#ifndef __BOAR_LIST_H__
#define __BOAR_LIST_H__

typedef struct boar_list_node boar_list_node;

typedef struct boar_list {
    boar_list_node *head;
    int len;
} boar_list;

struct boar_list_node {
    void *value;
    boar_list_node *next;
};

boar_list *new_boar_list();
void boar_list_push(boar_list *list, void *value);
void boar_list_remove(boar_list *list, void *value);
int boar_list_len(boar_list *list);

#endif
