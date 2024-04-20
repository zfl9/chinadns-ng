#define _GNU_SOURCE
#include "misc.h"
#include "uthash.h"
#include <signal.h>
#include <sys/stat.h>

const void *SIG_IGNORE(void) {
    return SIG_IGN;
}

const void *SIG_DEFAULT(void) {
    return SIG_DFL;
}

const void *SIG_ERROR(void) {
    return SIG_ERR;
}

ssize_t fstat_size(int fd) {
    struct stat st;
    if (fstat(fd, &st) == 0)
        return st.st_size;
    return -1;
}

uint calc_hashv(const void *ptr, size_t len) {
    uint hashv = 0;
    HASH_FUNCTION(ptr, len, hashv);
    return hashv;
}
