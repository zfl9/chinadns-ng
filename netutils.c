#define _GNU_SOURCE
#include "netutils.h"
#include "logutils.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

// TODO
