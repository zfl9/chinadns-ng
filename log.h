#pragma once

#include <stdio.h>
#include <time.h>
#include "opt.h"

#define LOGI(fmt, args...) ({ \
    struct tm *t_ = localtime(&(time_t){time(NULL)}); \
    printf("\e[1;32m%04d-%02d-%02d %02d:%02d:%02d I:\e[0m [%s] " fmt "\n", \
            t_->tm_year + 1900, t_->tm_mon + 1, t_->tm_mday, \
            t_->tm_hour,        t_->tm_min,     t_->tm_sec, \
            __func__, ##args); \
})

#define LOGE(fmt, args...) ({ \
    struct tm *t_ = localtime(&(time_t){time(NULL)}); \
    printf("\e[1;35m%04d-%02d-%02d %02d:%02d:%02d E:\e[0m [%s] " fmt "\n", \
            t_->tm_year + 1900, t_->tm_mon + 1, t_->tm_mday, \
            t_->tm_hour,        t_->tm_min,     t_->tm_sec, \
            __func__, ##args); \
})

#define LOGV(fmt, args...) ({ \
    IF_VERBOSE LOGI(fmt, ##args); \
})
