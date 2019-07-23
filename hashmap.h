#ifndef CHINADNS_NG_HASHMAP_H
#define CHINADNS_NG_HASHMAP_H

#include <stdint.h>
#include "uthash.h"

/* identity of dns message */
typedef uint16_t hashmap_key_t; 

/* file descriptor of timer */
typedef int hashmap_value_t;

/* hashmap structure definition */
typedef struct {
    hashmap_key_t key;
    hashmap_value_t value;
    UT_hash_handle hh; /* used by uthash */
} hashmap_t, hashmap_entry_t;

/* create a empty hashmap */
hashmap_t* hashmap_new(void);

/* put key and value in hashmap */
void hashmap_put(hashmap_t *hashmap, hashmap_key_t key, hashmap_value_t value);

/* get value by key from hashmap */
hashmap_value_t hashmap_get(const hashmap_t *hashmap, hashmap_key_t key);

/* delete entry by key from hashmap */
void hashmap_del(hashmap_t *hashmap, hashmap_key_t key);

/* delete all entry from hashmap, including head entry */
void hashmap_free(hashmap_t *hashmap);

#endif
