#!/usr/bin/env bash
# Bring up the USB Wi-Fi dongle (AIC8800D80 or RTL8852BU) as feth80: load firmware, join WiFi, DHCP.
# usage (as root): scripts/usbwifi-up.sh <SSID>   (passphrase is prompted; empty = open network)
# shortcut: assumes the dongle is adapter slot 0 (feth80), the first one this Mac has seen
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSID="${1:?usage: $0 <SSID>}"
[[ $EUID -eq 0 ]] || { echo "need root" >&2; exit 1; }

# AIC8800D80 still in its mass-storage boot mode (0x5723 = 22307): push its firmware first
if ioreg -p IOUSB -l | grep -q '"idProduct" = 22307'; then
  "$ROOT/build/usbwifid" fwload --once --fw-dir "$ROOT/fw/aic8800D80" --lock-file /tmp/aicfw.lock
fi

# network service on feth80 = shows in System Settings > Network; configd does DHCP when link goes up
"$ROOT/build/usbwifi_netsvc" install

export LKPI_FW_DIR="${LKPI_FW_DIR:-$ROOT/fw}" # RTL8852BU firmware from the repo, not the installed copy

read -rsp "Passphrase for $SSID: " PASS; echo
trap 'ifconfig feth80 destroy 2>/dev/null || true; ifconfig feth81 destroy 2>/dev/null || true' EXIT
"$ROOT/build/usbwifid" connect "$SSID" ${PASS:+"$PASS"} --no-dhcp --stay
