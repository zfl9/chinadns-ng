#pragma once

#include <stdio.h>
#include <time.h>

#ifndef LOG_FILENAME
#define LOG_FILENAME __FILE__
#endif

const struct tm *get_tm(void);

#define log_write(color, level, fmt, args...) ({ \
    const struct tm *tm_ = get_tm(); \
    printf("\e[" color ";1m%d-%02d-%02d %02d:%02d:%02d " level "\e[0m " \
        "\e[1m[%s:%d %s]\e[0m " fmt "\n", \
        tm_->tm_year + 1900, tm_->tm_mon + 1, tm_->tm_mday, \
        tm_->tm_hour,        tm_->tm_min,     tm_->tm_sec, \
        LOG_FILENAME, __LINE__, __func__, ##args); \
})

#define log_info(fmt, args...) \
    log_write("32", "I", fmt, ##args)

#define log_warning(fmt, args...) \
    log_write("33", "W", fmt, ##args)

#define log_error(fmt, args...) \
    log_write("35", "E", fmt, ##args)
