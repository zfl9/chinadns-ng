#!/bin/bash
echo "create chnroute6 hash:net hashsize 64 family inet6" >chnroute6.ipset
reserved_ipaddrs=(
    ::/128
    ::1/128
    ::ffff:0:0/96
    ::ffff:0:0:0/96
    64:ff9b::/96
    100::/64
    2001::/32
    2001:20::/28
    2001:db8::/32
    2002::/16
    fc00::/7
    fe80::/10
    ff00::/8
)
for reserved_ipaddr in "${reserved_ipaddrs[@]}"; do echo "add chnroute6 $reserved_ipaddr" >>chnroute6.ipset; done
curl -sSkL 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest' | grep CN | grep ipv6 | awk -F'|' '{printf("add chnroute6 %s/%d\n", $4, $5)}' >>chnroute6.ipset
