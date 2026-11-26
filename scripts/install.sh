#!/usr/bin/env bash
# Install AIC8800D80 auto-start: plug the dongle in -> firmware loads -> joins saved WiFi -> "UGREEN WiFi" service gets DHCP.
# usage (as root): scripts/install.sh <SSID>        (passphrase prompted; empty = open network)
#                  scripts/install.sh --uninstall
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN=/Library/PrivilegedHelperTools/aic8800-mac
SUP="/Library/Application Support/AIC8800"
LABELS=(com.aic8800mac.fwload com.aic8800mac.wifi)
[[ $EUID -eq 0 ]] || { echo "need root" >&2; exit 1; }

for l in "${LABELS[@]}"; do
  launchctl bootout "system/$l" 2>/dev/null || true
done

if [[ "${1:-}" == "--uninstall" ]]; then
  [[ -x "$BIN/aic_netsvc" ]] && "$BIN/aic_netsvc" remove || true
  for l in "${LABELS[@]}"; do rm -f "/Library/LaunchDaemons/$l.plist"; done
  rm -rf "$BIN" "$SUP"
  ifconfig feth80 destroy 2>/dev/null || true
  ifconfig feth81 destroy 2>/dev/null || true
  echo "uninstalled"
  exit 0
fi

SSID="${1:?usage: $0 <SSID> | --uninstall}"
[[ -x "$ROOT/build/aic8800_wifi" ]] || { echo "run make first" >&2; exit 1; }

install -d -m 755 "$BIN" "$SUP/fw"
install -m 755 "$ROOT"/build/{aic8800_fwload,aic8800_wifi,aic_netsvc} "$BIN/"
rm -rf "$SUP/fw/aic8800D80" && cp -R "$ROOT/fw/aic8800D80" "$SUP/fw/"

read -rsp "Passphrase for $SSID: " PASS; echo
"$BIN/aic8800_wifi" save "$SSID" ${PASS:+"$PASS"}
unset PASS
"$BIN/aic_netsvc" install

plist() { # label, args...
  local label=$1; shift
  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n'
    printf '<key>Label</key><string>%s</string>\n<key>ProgramArguments</key><array>\n' "$label"
    for a in "$@"; do printf '<string>%s</string>\n' "$a"; done
    printf '</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>5</integer>\n'
    printf '<key>StandardOutPath</key><string>/var/log/%s.log</string>\n<key>StandardErrorPath</key><string>/var/log/%s.log</string>\n</dict></plist>\n' "$label" "$label"
  } > "/Library/LaunchDaemons/$label.plist"
  chmod 644 "/Library/LaunchDaemons/$label.plist"
  launchctl bootstrap system "/Library/LaunchDaemons/$label.plist"
}
plist com.aic8800mac.fwload "$BIN/aic8800_fwload" --daemon --fw-dir "$SUP/fw/aic8800D80" --post-wake-delay-ms 1200
plist com.aic8800mac.wifi "$BIN/aic8800_wifi" --daemon

echo "installed. logs: /var/log/com.aic8800mac.{fwload,wifi}.log"
