#!/bin/bash
set -o errexit
set -o pipefail

# exit if curl failed
data="$(curl -4fsSkL https://raw.githubusercontent.com/pexcn/daily/gh-pages/chnroute/chnroute.txt)"

echo "add table inet global" >chnroute.nftset
echo "add set inet global chnroute { type ipv4_addr; flags interval; }" >>chnroute.nftset
echo "$data" | awk '{printf("add element inet global chnroute { %s }\n", $0)}' >>chnroute.nftset
