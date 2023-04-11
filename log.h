#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "opt.h"

#define log_write(color, level, fmt, args...) ({ \
    const struct tm *tm_ = localtime(&(time_t){time(NULL)}); \
    printf("\e[" color ";1m%04d-%02d-%02d %02d:%02d:%02d " level "\e[0m " \
        "\e[1m[" __FILE__ ":" literal(__LINE__) " %s]\e[0m " fmt "\n", \
        tm_->tm_year + 1900, tm_->tm_mon + 1, tm_->tm_mday, \
        tm_->tm_hour,        tm_->tm_min,     tm_->tm_sec, \
        __func__, ##args); \
})

#ifdef DEBUG
#define log_debug(fmt, args...) \
    log_write("34", "D", fmt, ##args)
#else
#define log_debug(...) /* nothing */
#endif /* DEBUG */

#define log_verbose(fmt, args...) ({ \
    if_verbose log_info(fmt, ##args); \
})

#define log_info(fmt, args...) \
    log_write("32", "I", fmt, ##args)

#define log_warning(fmt, args...) \
    log_write("33", "W", fmt, ##args)

#define log_error(fmt, args...) \
    log_write("35", "E", fmt, ##args)

#define log_fatal(fmt, args...) ({ \
    log_write("31", "F", fmt, ##args); \
    fflush(NULL); \
    abort(); \
}) 
