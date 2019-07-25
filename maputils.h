#ifndef CHINADNS_NG_MAPUTILS_H
#define CHINADNS_NG_MAPUTILS_H

#define _GNU_SOURCE
#include "uthash.h"
#include <stdint.h>
#include <netinet/in.h>
#undef _GNU_SOURCE

/* hash table structure typedef */
typedef struct {
    uint16_t unique_msgid; /* key */
    uint16_t origin_msgid;
    struct sockaddr_in6 source_addr;
    UT_hash_handle hh; /* meta data */
} hashmap_t, hashentry_t;

/* create a new hashmap */
hashmap_t* hashmap_new(void);

/* put key and value to hashmap */
void hashmap_put(hashmap_t *hashmap, uint16_t unique_msgid, uint16_t origin_msgid, const struct sockaddr_in6 *source_addr);

/* get entry_ptr by unique_msgid */
const hashentry_t* hashmap_get(const hashmap_t *hashmap, uint16_t unique_msgid);

/* delete and free entry by unique_msgid */
void hashmap_del(hashmap_t *hashmap, uint16_t unique_msgid);

/* delete and free all entries in hashmap */
void hashmap_free(hashmap_t *hashmap);

#endif
