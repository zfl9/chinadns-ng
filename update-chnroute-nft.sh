#!/bin/bash
set -o errexit
set -o pipefail
echo "add table inet global" >chnroute.nftset
echo "add set inet global chnroute { type ipv4_addr; flags interval; }" >>chnroute.nftset
curl -4sSkL 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest' | grep CN | grep ipv4 | awk -F'|' \
    '{printf("add element inet global chnroute { %s/%d }\n", $4, 32-log($5)/log(2))}' >>chnroute.nftset
