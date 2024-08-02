#!/bin/bash

CC='zig cc'
CFLAGS='-std=c99 -Wall -Wextra -Wvla -O3 -fno-strict-aliasing -ffunction-sections -fdata-sections -Wl,--gc-sections -s'
INCLUDE='-I../src'
OBJS='dns_cache_mgr.c ../src/dns.c'
MAIN='dns_cache_mgr'

for arg in "$@"; do
    [[ "$arg" = *=* ]] && declare "$arg"
done

set -x

$CC $CFLAGS $INCLUDE $OBJS -o $MAIN
