#define _GNU_SOURCE
#include "log.h"

const struct tm *get_tm(void) {
    return localtime(&(time_t){time(NULL)});
}
