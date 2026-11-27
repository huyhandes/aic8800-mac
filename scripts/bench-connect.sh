#!/usr/bin/env bash
# Time DISCONNECT -> RECONNECT (saved profile) -> associated -> DHCP lease -> first ping, N rounds.
# No root needed (socket is root:admin 0660). usage: scripts/bench-connect.sh [rounds]
set -euo pipefail
SOCK=/var/run/aic8800_wifi.sock
LOG=/var/log/com.aic8800mac.wifi.log
N=${1:-3}
cmd() { printf '%s\n' "$1" | nc -U -w 30 "$SOCK"; }
now() { perl -MTime::HiRes=time -e 'printf "%.2f", time'; }
ip4() { ifconfig feth80 2>/dev/null | awk '/inet /{print $2}'; }

for r in $(seq 1 "$N"); do
  cmd DISCONNECT >/dev/null
  for _ in {1..50}; do [[ -z "$(ip4)" ]] && break; sleep 0.1; done
  start=$(now)
  # stamp each daemon log line with seconds since start
  tail -n0 -F "$LOG" 2>/dev/null | perl -MTime::HiRes=time -ne "BEGIN{\$|=1} printf \"  +%5.2fs %s\", time-$start, \$_ unless /^aicd: rx/" &
  tp=$!
  cmd RECONNECT >/dev/null
  t_ip=""; t_ping=""
  for _ in {1..1500}; do
    if [[ -z "$t_ip" && -n "$(ip4)" ]]; then t_ip=$(now); fi
    if [[ -n "$t_ip" ]] && ping -c1 -t1 -b feth80 1.1.1.1 >/dev/null 2>&1; then t_ping=$(now); break; fi
    sleep 0.02
  done
  sleep 0.3; kill "$tp" 2>/dev/null; wait "$tp" 2>/dev/null || true
  echo "round $r: ip=$(awk "BEGIN{print ${t_ip:-0}-$start}")s ping=$(awk "BEGIN{print ${t_ping:-0}-$start}")s ($(ip4))"
done
