#define _GNU_SOURCE
#include "maputils.h"
#include "logutils.h"
#include <stdlib.h>
#include <string.h>
#undef _GNU_SOURCE

/* create a new hashmap */
hashmap_t* hashmap_new(void) {
    hashmap_t *hashmap = NULL;
    hashentry_t *hashentry = calloc(1, sizeof(hashentry_t));
    HASH_ADD(hh, hashmap, unique_msgid, sizeof(uint16_t), hashentry);
    return hashmap;
}

/* put key and value to hashmap */
hashentry_t* hashmap_put(hashmap_t *hashmap, uint16_t unique_msgid, uint16_t origin_msgid, int query_timerfd, const struct sockaddr_in6 *source_addr) {
    hashentry_t *hashentry = NULL;
    HASH_FIND(hh, hashmap, &unique_msgid, sizeof(uint16_t), hashentry);
    if (!hashentry) {
        hashentry = malloc(sizeof(hashentry_t));
        hashentry->unique_msgid = unique_msgid;
        hashentry->origin_msgid = origin_msgid;
        hashentry->query_timerfd = query_timerfd;
        memcpy(&hashentry->source_addr, source_addr, sizeof(struct sockaddr_in6));
        HASH_ADD(hh, hashmap, unique_msgid, sizeof(uint16_t), hashentry);
    } else {
        LOGERR("[hashmap_put] key already exists in hashmap, duplicate key: %hu", unique_msgid);
        exit(1);
    }
    return hashentry;
}

/* get entry_ptr by unique_msgid */
hashentry_t* hashmap_get(hashmap_t *hashmap, uint16_t unique_msgid) {
    hashentry_t *hashentry = NULL;
    HASH_FIND(hh, hashmap, &unique_msgid, sizeof(uint16_t), hashentry);
    return hashentry;
}

/* delete and free the entry from hashmap */
void hashmap_del(hashmap_t *hashmap, hashentry_t *hashentry) {
    HASH_DEL(hashmap, hashentry);
    free(hashentry);
}

/* delete and free all entries from hashmap */
void hashmap_free(hashmap_t *hashmap) {
    hashentry_t *curr_entry = NULL, *temp_entry = NULL;
    HASH_ITER(hh, hashmap, curr_entry, temp_entry) {
        HASH_DEL(hashmap, curr_entry);
        free(curr_entry);
    }
}
