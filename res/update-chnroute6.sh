#!/bin/bash
set -o errexit
set -o pipefail

# exit if curl failed
data="$(curl -4fsSkL https://ftp.apnic.net/stats/apnic/delegated-apnic-latest | grep CN | grep ipv6)"

echo "create chnroute6 hash:net family inet6" >chnroute6.ipset
echo "$data" | awk -F'|' '{printf("add chnroute6 %s/%d\n", $4, $5)}' >>chnroute6.ipset
