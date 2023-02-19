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
  local lines="$(wc -l <"${dir}/${file}")"
  curl -sSL --create-dirs --output-dir $dir -O "$url" || return 1
  info "update ${file}: ${lines} -> $(wc -l <"${dir}/${file}")."
}

update_rules() {
  _update_rule https://github.com/pexcn/daily/raw/gh-pages/chnroute/chnroute.txt || return 1
  _update_rule https://github.com/pexcn/daily/raw/gh-pages/chnroute/chnroute6.txt || return 1
  _update_rule https://github.com/pexcn/daily/raw/gh-pages/gfwlist/gfwlist.txt || return 1
  _update_rule https://github.com/pexcn/daily/raw/gh-pages/chinalist/chinalist.txt || return 1
}

_is_exist_ipset() {
  ipset list -n "$1" >/dev/null 2>&1
}

# FIXME: don't hardcode ipset name.
load_ipsets() {
  local ipset4="chnroute"
  if _is_exist_ipset $ipset4; then
    ipset flush $ipset4
    info "ipset4: $ipset4 flushed."
  else
    ipset create $ipset4 hash:net hashsize 64 family inet
    info "ipset4: $ipset4 created."
  fi
  ipset restore <<-EOF
	$(sed "s/^/add $ipset4 /" </etc/chinadns-ng/chnroute.txt)
	EOF
  info "ipset4: load to $ipset4 done."

  local ipset6="chnroute6"
  if _is_exist_ipset $ipset6; then
    ipset flush $ipset6
    info "ipset6: $ipset6 flushed."
  else
    ipset create $ipset6 hash:net hashsize 64 family inet6
    info "ipset6: $ipset6 created."
  fi
  ipset restore <<-EOF
	$(sed "s/^/add $ipset6 /" </etc/chinadns-ng/chnroute6.txt)
	EOF
  info "ipset6: load to $ipset6 done."
}

# FIXME: don't hardcode ipset name.
destroy_ipsets() {
  local ipset4="chnroute"
  ipset flush "$ipset4"
  ipset destroy "$ipset4"
  info "ipset4: $ipset4 destroyed."

  local ipset6="chnroute6"
  ipset flush "$ipset6"
  ipset destroy "$ipset6"
  info "ipset6: $ipset6 destroyed."
}

_is_reuse_port() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -r | --reuse-port) return 0 ;;
      *) shift ;;
    esac
  done
  return 1
}

_get_cpu_cores() {
  grep -c "^processor" /proc/cpuinfo
}

start_process() {
  local cores="$(_get_cpu_cores)"
  if _is_reuse_port "$@" && [ "$cores" -gt 1 ]; then
    info "start $cores chinadns-ng processes."
    # shellcheck disable=SC2034
    for i in $(seq 1 "$cores"); do
      chinadns-ng "$@" &
    done
  else
    info "start chinadns-ng process."
    chinadns-ng "$@" &
  fi
}

stop_process() {
  kill "$(pidof chinadns-ng)"
  info "terminate chinadns-ng processes."

  # ensure child process terminate completely, avoid <defunct> processes
  sleep 3
}

graceful_stop() {
  warn "caught SIGTERM or SIGINT signal, graceful stopping..."
  stop_process
  destroy_ipsets

  # exit infinite loop
  exit 0
}

start_chinadns_ng() {
  trap 'graceful_stop' TERM INT

  load_ipsets
  start_process "$@"

  if [ "$RULES_UPDATE_INTERVAL" = 0 ]; then
    wait
  else
    while true; do
      sleep "$RULES_UPDATE_INTERVAL" &
      wait $!
      if update_rules; then
        warn "update rules success, restart chinadns-ng..."
        stop_process
        load_ipsets
        start_process "$@"
      else
        error "update rules failed, skip restart chinadns-ng."
      fi
    done
  fi
}

start_chinadns_ng "$@"
