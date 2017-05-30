#ifndef __BOAR_HASHMAP_H__
#define __BOAR_HASHMAP_H__

#include "boar.h"
#include "boar_list.h"

typedef uint32_t (*HASHFUNC)(void *key);

#define MAX_CAP (1 << 16)
#define MAX_CHAIN 8

typedef struct {
    uint32_t cap;
    boar_list **arr;
    HASHFUNC hash;
} boar_hashmap;

boar_hashmap *new_boar_hashmap(uint32_t init_cap, HASHFUNC hash);
void boar_hashmap_insert(boar_hashmap *hashmap, void *key, void *value);
void *boar_hashmap_find(boar_hashmap *hashmap, void *key);

#endif
