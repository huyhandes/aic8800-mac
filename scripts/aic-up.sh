#!/usr/bin/env bash
# Bring up the UGREEN AIC8800D80 dongle as feth80: load firmware, join WiFi, DHCP.
# usage (as root): scripts/aic-up.sh <SSID>   (passphrase is prompted; empty = open network)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSID="${1:?usage: $0 <SSID>}"
[[ $EUID -eq 0 ]] || { echo "need root" >&2; exit 1; }

# 0x8d85 = 36229: firmware already running, skip the loader
if ! ioreg -p IOUSB -l | grep -q '"idProduct" = 36229'; then
  "$ROOT/build/aic8800_fwload" --once --fw-dir "$ROOT/fw/aic8800D80" --lock-file /tmp/aicfw.lock
fi

# network service on feth80 = shows in System Settings > Network; configd does DHCP when link goes up
"$ROOT/build/aic_netsvc" install

read -rsp "Passphrase for $SSID: " PASS; echo
trap 'ifconfig feth80 destroy 2>/dev/null || true; ifconfig feth81 destroy 2>/dev/null || true' EXIT
"$ROOT/build/aic8800_wifi" connect "$SSID" ${PASS:+"$PASS"} --no-dhcp --stay
