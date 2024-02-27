#include "misc.h"
#include <signal.h>

const void *SIG_IGNORE(void) {
    return SIG_IGN;
}

const void *SIG_DEFAULT(void) {
    return SIG_DFL;
}

const void *SIG_ERROR(void) {
    return SIG_ERR;
}
