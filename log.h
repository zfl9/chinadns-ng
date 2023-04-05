#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "opt.h"

#define log_write(color, level, fmt, args...) ({ \
    struct tm *t_ = localtime(&(time_t){time(NULL)}); \
    printf("\e[" color ";1m%04d-%02d-%02d %02d:%02d:%02d " level "\e[0m \e[1m[%s:%d %s]\e[0m " fmt "\n", \
            t_->tm_year + 1900, t_->tm_mon + 1, t_->tm_mday, \
            t_->tm_hour,        t_->tm_min,     t_->tm_sec, \
            __FILE__, __LINE__, __func__, ##args); \
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
