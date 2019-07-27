#!/bin/bash
echo "create chnroute hash:net family inet" >chnroute.ipset
reserved_ipaddrs=(
    0.0.0.0/8
    10.0.0.0/8
    100.64.0.0/10
    127.0.0.0/8
    169.254.0.0/16
    172.16.0.0/12
    192.0.0.0/24
    192.0.2.0/24
    192.88.99.0/24
    192.168.0.0/16
    198.18.0.0/15
    198.51.100.0/24
    203.0.113.0/24
    224.0.0.0/4
    240.0.0.0/4
    255.255.255.255/32
)
for reserved_ipaddr in "${reserved_ipaddrs[@]}"; do echo "add chnroute $reserved_ipaddr" >>chnroute.ipset; done
curl 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest' | grep CN | grep ipv4 | awk -F'|' '{printf("add chnroute %s/%d\n", $4, 32-log($5)/log(2))}' >>chnroute.ipset
