#!/bin/bash

if command -v zig >/dev/null; then
    CC='zig cc'
elif command -v gcc >/dev/null; then
    CC='gcc'
elif command -v clang >/dev/null; then
    CC='clang'
else
    echo "please install 'gcc' or 'clang' or 'zig'" 1>&2
    exit 1
fi

CFLAGS='-std=c99 -Wall -Wextra -Wvla -O3 -fno-strict-aliasing -ffunction-sections -fdata-sections -Wl,--gc-sections -s'
OBJS='dns_cache_mgr.c ../src/dns.c'
MAIN='dns_cache_mgr'

for arg in "$@"; do
    [[ "$arg" = *=* ]] && declare "$arg"
done

set -x

$CC $CFLAGS $OBJS -o $MAIN
