#!/bin/bash
set -o errexit
set -o pipefail

# exit if curl failed
url='https://raw.githubusercontent.com/pexcn/daily/gh-pages/gfwlist/gfwlist.txt'
data="$(curl -4fsSkL "$url" | grep -v -e '^[[:space:]]*$' -e '^[[:space:]]*#')"

get_data() {
    echo "$data"
    # echo "google.cn"
    echo "googleapis.cn"
}

get_data | sort | uniq >gfwlist.txt
