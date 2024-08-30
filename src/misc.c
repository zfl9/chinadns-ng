#define _GNU_SOURCE
#include "misc.h"
#include "uthash.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

void sig_register(int sig, sighandler_t handler) {
    struct sigaction act;
    act.sa_handler = handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(sig, &act, NULL);
}

const void *SIG_IGNORE(void) {
    return SIG_IGN;
}

const void *SIG_DEFAULT(void) {
    return SIG_DFL;
}

bool is_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0)
        return S_ISDIR(st.st_mode);
    return false;
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

bool has_aes(void) {
    bool found = false;

    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) goto out;

    char buf[10];
    while (fscanf(f, "%9s", buf) > 0) {
        if (strstr(buf, "aes")) {
            found = true;
            break;
        }
    }

out:
    if (f) fclose(f);
    return found;
}

u64 monotime(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (u64)t.tv_sec * 1000 + (u64)t.tv_nsec / 1000000;
}
