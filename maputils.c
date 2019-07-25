#define _GNU_SOURCE
#include "maputils.h"
#include "logutils.h"
#include <stdlib.h>
#include <string.h>
#undef _GNU_SOURCE

/* create a new hashmap */
hashmap_t* hashmap_new(void) {
    // TODO
    return NULL;
}

/* put key and value to hashmap */
void hashmap_put(hashmap_t *hashmap, uint16_t unique_msgid, uint16_t origin_msgid, const struct sockaddr_in6 *source_addr) {
    // TODO
}

/* get entry_ptr by unique_msgid */
const hashentry_t* hashmap_get(const hashmap_t *hashmap, uint16_t unique_msgid) {
    // TODO
    return NULL;
}

/* delete and free entry by unique_msgid */
void hashmap_del(hashmap_t *hashmap, uint16_t unique_msgid) {
    // TODO
}

/* delete and free all entries in hashmap */
void hashmap_free(hashmap_t *hashmap) {
    // TODO
}
