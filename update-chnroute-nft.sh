#!/bin/bash
set -o errexit
set -o pipefail

# exit if curl failed
data="$(curl -4fsSkL https://ftp.apnic.net/stats/apnic/delegated-apnic-latest | grep CN | grep ipv4)"

echo "add table inet global" >chnroute.nftset
echo "add set inet global chnroute { type ipv4_addr; flags interval; }" >>chnroute.nftset
awk -F'|' '{printf("add element inet global chnroute { %s/%d }\n", $4, 32-log($5)/log(2))}' <<<"$data" >>chnroute.nftset
