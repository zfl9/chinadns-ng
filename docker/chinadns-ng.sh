#!/bin/sh

info() {
  local green='\e[0;32m'
  local clear='\e[0m'
  local time=$(date '+%Y-%m-%d %T')
  printf "${green}[${time}] [INFO]: ${clear}%s\n" "$*"
}

warn() {
  local yellow='\e[1;33m'
  local clear='\e[0m'
  local time=$(date '+%Y-%m-%d %T')
  printf "${yellow}[${time}] [WARN]: ${clear}%s\n" "$*" >&2
}

error() {
  local red='\e[0;31m'
  local clear='\e[0m'
  local time=$(date '+%Y-%m-%d %T')
  printf "${red}[${time}] [ERROR]: ${clear}%s\n" "$*" >&2
}

_update_list() {
  local url="$1"
  local file="$(basename $url)"
  local dir="/etc/chinadns-ng"
  local lines="$(wc -l < ${dir}/${file})"
  curl -sSL --create-dirs --output-dir $dir -O $url
  info "update ${file}: ${lines} -> $(wc -l < ${dir}/${file})"
}

update_lists() {
  _update_list https://github.com/pexcn/daily/raw/gh-pages/chnroute/chnroute.txt
  _update_list https://github.com/pexcn/daily/raw/gh-pages/chnroute/chnroute6.txt
  _update_list https://github.com/pexcn/daily/raw/gh-pages/gfwlist/gfwlist.txt
  _update_list https://github.com/pexcn/daily/raw/gh-pages/chinalist/chinalist.txt
  # TODO: cannot restart chinadns-ng if download fails
  # update_list xxx || return 1 ?
}

restart_process() {
  kill $(pidof chinadns-ng)
  sleep 5
  chinadns-ng "$@" &
}

graceful_stop() {
  kill $(pidof chinadns-ng)

  # make sure signal can delivered to child process, avoid <defunct> processes
  sleep 5
  # exit infinite loop
  exit 0
}

start_chinadns_ng() {
  trap 'graceful_stop' SIGTERM SIGINT

  chinadns-ng "$@" &

  while true; do
    sleep 10
    update_lists
    restart_process
    #if update_lists; then
    #  restart_process
    #fi
  done
}

start_chinadns_ng "$@"
