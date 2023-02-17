#pragma once

#include <stdio.h>
#include <time.h>
#include "opt.h"
#include "misc.h"

#define LOGI(fmt, args...) ({ \
    struct tm *tm = localtime(&(time_t){time(NULL)}); \
    printf("\e[1;32m%04d-%02d-%02d %02d:%02d:%02d I:\e[0m [%s] " fmt "\n", \
            tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, \
            tm->tm_hour,        tm->tm_min,     tm->tm_sec, \
            __func__, ##args); \
})

#define LOGE(fmt, args...) ({ \
    struct tm *tm = localtime(&(time_t){time(NULL)}); \
    printf("\e[1;35m%04d-%02d-%02d %02d:%02d:%02d E:\e[0m [%s] " fmt "\n", \
            tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, \
            tm->tm_hour,        tm->tm_min,     tm->tm_sec, \
            __func__, ##args); \
})

#define LOGV(fmt, args...) ({ \
    unlikely_if (g_verbose) LOGI(fmt, ##args); \
})
