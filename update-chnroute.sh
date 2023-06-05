#!/bin/bash
set -o errexit
set -o pipefail

# exit if curl failed
data="$(curl -4fsSkL https://ftp.apnic.net/stats/apnic/delegated-apnic-latest | grep CN | grep ipv4)"

echo "create chnroute hash:net family inet" >chnroute.ipset
awk -F'|' '{printf("add chnroute %s/%d\n", $4, 32-log($5)/log(2))}' <<<"$data" >>chnroute.ipset
