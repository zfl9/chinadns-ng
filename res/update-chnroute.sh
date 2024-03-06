#!/bin/bash
set -o errexit
set -o pipefail

# exit if curl failed
data="$(curl -4fsSkL https://raw.githubusercontent.com/pexcn/daily/gh-pages/chnroute/chnroute.txt)"

echo "create chnroute hash:net family inet" >chnroute.ipset
echo "$data" | awk '{printf("add chnroute %s\n", $0)}' >>chnroute.ipset
