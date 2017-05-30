#include "boar_hashmap.h"
#include <stdlib.h>

struct kv {
    void *key;
    void *value;
};

static uint32_t default_hash(void *key) {
    return (uint32_t)key;
}

boar_hashmap *new_boar_hashmap(uint32_t init_cap, HASHFUNC hash) {
    boar_hashmap *hashmap = malloc(sizeof(*hashmap));
    hashmap->cap = init_cap;
    hashmap->arr = malloc(hashmap->cap * sizeof(*hashmap->arr));
    for (int i = 0; i < init_cap; i++) {
        hashmap->arr[i] = new_boar_list();
    }
    if (hash)
        hashmap->hash = hash;
    else
        hashmap->hash = default_hash;

    return hashmap;
}

static void resize(boar_hashmap *hashmap) {
    uint32_t old_cap = hashmap->cap;
    hashmap->cap *= 2;
    if (hashmap->cap > MAX_CAP)
        return;

    boar_list **arr = malloc(hashmap->cap * sizeof(*hashmap->arr));

    for (uint32_t i = 0; i < old_cap; i++) {
        boar_list *list = hashmap->arr[i];

        boar_list_node *ptr;
        for (ptr = list->head; ptr; ptr = ptr->next) {
            struct kv *kv = ptr->value;
            uint32_t hs = hashmap->hash(kv->key);
            boar_list_push(arr[hs % hashmap->cap], kv);
        }
    }

    free(hashmap->arr);
    hashmap->arr = arr;
}

static struct kv *new_kv(void *key, void *value) {
    struct kv *kv = malloc(sizeof(*kv));
    kv->key = key;
    kv->value = value;
    return kv;
}

void boar_hashmap_insert(boar_hashmap *hashmap, void *key, void *value) {
    uint32_t hs = hashmap->hash(key);
    boar_list *list = hashmap->arr[hs % hashmap->cap];
    boar_list_push(list, new_kv(key, value));
    if (boar_list_len(list) > MAX_CHAIN)
        resize(hashmap);
}

void *boar_hashmap_find(boar_hashmap *hashmap, void *key) {
    uint32_t hs = hashmap->hash(key);
    boar_list *list = hashmap->arr[hs % hashmap->cap];

    boar_list_node *ptr;
    for (ptr = list->head; ptr; ptr = ptr->next) {
        struct kv *kv = ptr->value;
        if (kv->key == key)
            return kv->value;
    }

    return 0;
}
