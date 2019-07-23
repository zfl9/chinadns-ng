#define _GNU_SOURCE
#include "hashmap.h"
#include "logutils.h"
#include <stdlib.h>
#include <unistd.h>

hashmap_t* hashmap_new(void) {
    hashmap_t *hashmap = NULL;
    hashmap_entry_t *head_entry = calloc(1, sizeof(hashmap_entry_t));
    HASH_ADD(hh, hashmap, key, sizeof(hashmap_key_t), head_entry);
    return hashmap;
}

void hashmap_put(hashmap_t *hashmap, hashmap_key_t key, hashmap_value_t value) {
    hashmap_entry_t *entry = NULL;
    HASH_FIND(hh, hashmap, &key, sizeof(hashmap_key_t), entry);
    if (!entry) {
        entry = malloc(sizeof(hashmap_entry_t));
        entry->key = key;
        entry->value = value;
        HASH_ADD(hh, hashmap, key, sizeof(hashmap_key_t), entry);
    } else {
        LOGERR("[hashmap_put] key already exists in the hashmap: %hu", key);
    }
}

hashmap_value_t hashmap_get(const hashmap_t *hashmap, hashmap_key_t key) {
    hashmap_entry_t *entry = NULL;
    HASH_FIND(hh, hashmap, &key, sizeof(hashmap_key_t), entry);
    return entry ? entry->value : -1;
}

/* please close timer fd before calling */
void hashmap_del(hashmap_t *hashmap, hashmap_key_t key) {
    hashmap_entry_t *entry = NULL;
    HASH_FIND(hh, hashmap, &key, sizeof(hashmap_key_t), entry);
    if (entry) {
        HASH_DEL(hashmap, entry);
        free(entry);
    }
}

/* close all timer fd */
void hashmap_free(hashmap_t *hashmap) {
    hashmap_entry_t *curr_entry = NULL, *temp_entry = NULL;
    HASH_ITER(hh, hashmap, curr_entry, temp_entry) {
        if (curr_entry->value > 0) close(curr_entry->value);
        HASH_DEL(hashmap, curr_entry);
        free(curr_entry);
    }
}
