#!/bin/sh

# shellcheck disable=SC2155,SC3043

info() {
  local green='\e[0;32m'
  local clear='\e[0m'
  local time="$(date '+%Y-%m-%d %T')"
  printf "${green}[${time}] [INFO]: ${clear}%s\n" "$*"
}

warn() {
  local yellow='\e[1;33m'
  local clear='\e[0m'
  local time="$(date '+%Y-%m-%d %T')"
  printf "${yellow}[${time}] [WARN]: ${clear}%s\n" "$*" >&2
}

error() {
  local red='\e[0;31m'
  local clear='\e[0m'
  local time="$(date '+%Y-%m-%d %T')"
  printf "${red}[${time}] [ERROR]: ${clear}%s\n" "$*" >&2
}

_update_rule() {
  local url="$1"
  local file="$(basename "$url")"
  local dir="/etc/chinadns-ng"
  local lines="$(wc -l < "${dir}/${file}")"
  curl -sSL --create-dirs --output-dir $dir -O "$url" || return 1
  info "update ${file}: ${lines} -> $(wc -l < "${dir}/${file}")"
}

update_rules() {
  _update_rule https://github.com/pexcn/daily/raw/gh-pages/chnroute/chnroute.txt || return 1
  _update_rule https://github.com/pexcn/daily/raw/gh-pages/chnroute/chnroute6.txt || return 1
  _update_rule https://github.com/pexcn/daily/raw/gh-pages/gfwlist/gfwlist.txt || return 1
  _update_rule https://github.com/pexcn/daily/raw/gh-pages/chinalist/chinalist.txt || return 1
}

stop_process() {
  kill "$(pidof chinadns-ng)"
  info "terminate chinadns-ng processes."

  # ensure child process terminate completely, avoid <defunct> processes
  sleep 5
}

restart_process() {
  stop_process

  # TODO: move `&` to invoker?
  chinadns-ng "$@" &
}

graceful_stop() {
  stop_process

  # exit infinite loop
  exit 0
}

start_chinadns_ng() {
  trap 'graceful_stop' TERM INT

  if [ "$RULES_UPDATE_INTERVAL" = 0 ]; then
    # try replace to: `exec chinadns-ng "$@"`
    # need test `docker stop ...` and `docker-compose up, then ctrl + c`
    chinadns-ng "$@" &
    wait
  else
    chinadns-ng "$@" &
    while true; do
      sleep "$RULES_UPDATE_INTERVAL"
      update_rules && restart_process "$@"
    done
  fi
}

start_chinadns_ng "$@"
