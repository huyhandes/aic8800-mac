#!/usr/bin/env bash
# Install USB Wifi (AIC8800D80 / RTL8852BU): plug dongle -> driver comes up -> the USB Wifi menu offers a
# network picker (or auto-joins the saved one) -> "USB Wi-Fi" network service gets DHCP.
# usage (as root): scripts/install.sh             copy build/ + set up (manual install)
#                  scripts/install.sh --setup     set up only (pkg postinstall: payload already in place)
#                  scripts/install.sh --uninstall
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN=/Library/PrivilegedHelperTools/aic8800-mac
SUP="/Library/Application Support/AIC8800"
APP="/Applications/USB Wifi.app"
OLD_APP=/Applications/AIC8800Menu.app # 1.0.x name
LABELS=(com.aic8800mac.fwload com.aic8800mac.wifi)
MENU_LABEL=com.aic8800mac.menu
[[ $EUID -eq 0 ]] || { echo "need root" >&2; exit 1; }

USER_NAME=$(stat -f %Su /dev/console)
USER_UID=$(id -u "$USER_NAME")
USER_HOME=$(dscl . -read "/Users/$USER_NAME" NFSHomeDirectory | awk '{print $2}')
AGENT="$USER_HOME/Library/LaunchAgents/$MENU_LABEL.plist"
CD_LABEL=com.aic8800mac.cdswitch
CD_AGENT="/Library/LaunchAgents/$CD_LABEL.plist"

# bootout returns before the job is gone; bootstrapping it again too early fails with "5: Input/output error"
unload() {
  launchctl bootout "$1" 2>/dev/null || true
  for _ in {1..20}; do launchctl print "$1" >/dev/null 2>&1 || return 0; sleep 0.5; done
}
for l in "${LABELS[@]}"; do unload "system/$l"; done
unload "gui/$USER_UID/$MENU_LABEL"
unload "gui/$USER_UID/$CD_LABEL"
pkill -x AIC8800Menu 2>/dev/null || true
pkill -x USBWifi 2>/dev/null || true
rm -rf "$OLD_APP"

if [[ "${1:-}" == "--uninstall" ]]; then
  [[ -x "$BIN/aic_netsvc" ]] && "$BIN/aic_netsvc" remove || true
  for l in "${LABELS[@]}"; do rm -f "/Library/LaunchDaemons/$l.plist"; done
  rm -rf "$BIN" "$SUP" "$APP" "$OLD_APP" "$AGENT" "$CD_AGENT"
  ifconfig feth80 destroy 2>/dev/null || true
  ifconfig feth81 destroy 2>/dev/null || true
  for p in com.aic8800mac.pkg com.aic8800mac.pkg.aic8800 com.aic8800mac.pkg.rtl8852bu com.aic8800mac.pkg.setup; do
    pkgutil --forget "$p" >/dev/null 2>&1 || true
  done
  echo "uninstalled"
  exit 0
fi

if [[ "${1:-}" != "--setup" ]]; then
  [[ -d "$ROOT/build/USBWifi.app" ]] || { echo "run make first" >&2; exit 1; }
  install -d -m 755 "$BIN" "$SUP/fw"
  install -S -m 755 "$ROOT"/build/{aic8800_fwload,aic8800_wifi,aic_netsvc,libusb-1.0.0.dylib} "$BIN/"
  rm -rf "$SUP/fw/aic8800D80" "$SUP/fw/rtw89" "$APP"
  for d in aic8800D80 rtw89; do [[ -d "$ROOT/fw/$d" ]] && cp -R "$ROOT/fw/$d" "$SUP/fw/"; done
  cp -R "$ROOT/build/USBWifi.app" "$APP"
fi

# 1.0.x named the service after one vendor; recreate it under the neutral name
networksetup -listallnetworkservices 2>/dev/null | grep -qx 'UGREEN WiFi' && "$BIN/aic_netsvc" remove
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
# the AIC8800 firmware loader only when that driver was chosen (the RTL8852BU driver lives in aic8800_wifi)
if [[ -x "$BIN/aic8800_fwload" && -d "$SUP/fw/aic8800D80" ]]; then
  plist com.aic8800mac.fwload "$BIN/aic8800_fwload" --daemon --fw-dir "$SUP/fw/aic8800D80" --post-wake-delay-ms 1200 --usb-settle-timeout-ms 8000
else
  rm -f /Library/LaunchDaemons/com.aic8800mac.fwload.plist
fi
plist com.aic8800mac.wifi "$BIN/aic8800_wifi" --daemon
chmod 644 /var/log/com.aic8800mac.wifi.log 2>/dev/null || true # readable from the app's "Open Wi-Fi Log"

# Realtek dongles boot as a "driver CD" (0bda:1a2b). Its USB interface sits behind the per-user Removable
# Volumes permission, which a daemon can never hold, so launchd runs the eject in the console user's session
# on each plug-in (as Windows' WifiAutoInstallSrv does on device arrival); the daemon detaches macOS's driver
if [[ -d "$SUP/fw/rtw89" ]]; then
  cat > "$CD_AGENT" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$CD_LABEL</string>
<key>ProgramArguments</key><array><string>$BIN/aic8800_wifi</string><string>cd-eject</string></array>
<key>LimitLoadToSessionType</key><string>Aqua</string>
<key>LaunchEvents</key><dict><key>com.apple.iokit.matching</key><dict><key>$CD_LABEL.realtek</key><dict>
<key>IOProviderClass</key><string>IOUSBHostDevice</string>
<key>idVendor</key><integer>3034</integer><key>idProduct</key><integer>6699</integer>
<key>IOMatchLaunchStream</key><true/>
</dict></dict></dict>
</dict></plist>
PL
  chmod 644 "$CD_AGENT"
  launchctl bootstrap "gui/$USER_UID" "$CD_AGENT" || true
else
  rm -f "$CD_AGENT"
fi

# menu app at login for the console user (same plist the app's "Launch at Login" toggle manages)
install -d -o "$USER_NAME" "$USER_HOME/Library/LaunchAgents"
cat > "$AGENT" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$MENU_LABEL</string>
<key>ProgramArguments</key><array><string>$APP/Contents/MacOS/USBWifi</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PL
chown "$USER_NAME" "$AGENT"
launchctl bootstrap "gui/$USER_UID" "$AGENT" || launchctl asuser "$USER_UID" open "$APP"

echo "installed. logs: /var/log/com.aic8800mac.{fwload,wifi}.log"
