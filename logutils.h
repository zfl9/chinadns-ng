#ifndef CHINADNS_NG_LOGUTILS_H
#define CHINADNS_NG_LOGUTILS_H

#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#undef _GNU_SOURCE

#define LOGINF(fmt, ...)                                                    \
    do {                                                                    \
        time_t curts = time(NULL);                                          \
        struct tm curtm; localtime_r(&curts, &curtm);                       \
        printf("\e[1;32m%04d-%02d-%02d %02d:%02d:%02d INF:\e[0m " fmt "\n", \
                curtm.tm_year + 1900, curtm.tm_mon + 1, curtm.tm_mday,      \
                curtm.tm_hour,        curtm.tm_min,     curtm.tm_sec,       \
                ##__VA_ARGS__);                                             \
    } while (0)

#define LOGERR(fmt, ...)                                                    \
    do {                                                                    \
        time_t curts = time(NULL);                                          \
        struct tm curtm; localtime_r(&curts, &curtm);                       \
        printf("\e[1;35m%04d-%02d-%02d %02d:%02d:%02d ERR:\e[0m " fmt "\n", \
                curtm.tm_year + 1900, curtm.tm_mon + 1, curtm.tm_mday,      \
                curtm.tm_hour,        curtm.tm_min,     curtm.tm_sec,       \
                ##__VA_ARGS__);                                             \
    } while (0)

#endif
