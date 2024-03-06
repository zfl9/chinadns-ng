#!/bin/bash
set -o errexit
set -o pipefail

# exit if curl failed
url='https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf'
data="$(curl -4fsSkL "$url" | grep -v -e '^[[:space:]]*$' -e '^[[:space:]]*#')"

echo "$data" | awk -F/ '{print $2}' | sort | uniq >chnlist.txt
