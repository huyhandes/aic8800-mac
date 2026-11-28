#!/usr/bin/env bash
# Install USB Wifi (AIC8800D80 / RTL8852BU): plug dongle -> driver comes up -> the USB Wifi menu offers a
# network picker (or auto-joins the saved one) -> "USB Wi-Fi" network service gets DHCP.
# usage (as root): scripts/install.sh             copy build/ + set up (manual install)
#                  scripts/install.sh --setup     set up only (pkg postinstall: payload already in place)
#                  scripts/install.sh --uninstall
#                  scripts/install.sh --clean       uninstall every version (1.0.x too) but keep the saved networks
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN=/Library/PrivilegedHelperTools/usbwifi
SUP="/Library/Application Support/USB Wifi"
APP="/Applications/USB Wifi.app"
LOG_TRIM=com.usbwifi.logtrim
LABELS=(com.usbwifi.wifi $LOG_TRIM)
MENU_LABEL=com.usbwifi.menu
[[ $EUID -eq 0 ]] || { echo "need root" >&2; exit 1; }

USER_NAME=$(stat -f %Su /dev/console)
USER_UID=$(id -u "$USER_NAME")
USER_HOME=$(dscl . -read "/Users/$USER_NAME" NFSHomeDirectory | awk '{print $2}')
AGENT="$USER_HOME/Library/LaunchAgents/$MENU_LABEL.plist"
CD_LABEL=com.usbwifi.cdswitch
CD_AGENT="/Library/LaunchAgents/$CD_LABEL.plist"

# bootout returns before the job is gone; bootstrapping it again too early fails with "5: Input/output error"
unload() {
  launchctl bootout "$1" 2>/dev/null || true
  for _ in {1..20}; do launchctl print "$1" >/dev/null 2>&1 || return 0; sleep 0.5; done
}
for l in "${LABELS[@]}"; do unload "system/$l"; done
unload "gui/$USER_UID/$MENU_LABEL"
unload "gui/$USER_UID/$CD_LABEL"
pkill -x USBWifi 2>/dev/null || true

# older installs used com.aic8800mac.* / aic8800-mac: remove them so two daemons never fight over the dongle
OLD=com.aic8800mac
OLD_SUP="/Library/Application Support/AIC8800"
for l in fwload wifi; do unload "system/$OLD.$l"; rm -f "/Library/LaunchDaemons/$OLD.$l.plist"; done
for l in menu cdswitch; do unload "gui/$USER_UID/$OLD.$l"; done
rm -f "$USER_HOME/Library/LaunchAgents/$OLD.menu.plist" "/Library/LaunchAgents/$OLD.cdswitch.plist" /var/log/$OLD.*.log
pkill -x AIC8800Menu 2>/dev/null || true
[[ -f "$OLD_SUP/wifi.conf" && ! -f "$SUP/wifi.conf" ]] && install -d -m 755 "$SUP" && mv "$OLD_SUP/wifi.conf" "$SUP/"
rm -rf /Library/PrivilegedHelperTools/aic8800-mac "$OLD_SUP" /Applications/AIC8800Menu.app
for p in $OLD.pkg $OLD.pkg.aic8800 $OLD.pkg.rtl8852bu $OLD.pkg.setup; do pkgutil --forget "$p" >/dev/null 2>&1 || true; done

if [[ "${1:-}" == "--uninstall" || "${1:-}" == "--clean" ]]; then
  for s in {0..15}; do # one network service + feth pair per adapter slot
    [[ -x "$BIN/usbwifi_netsvc" ]] && "$BIN/usbwifi_netsvc" remove - "feth$((80 + 2 * s))" >/dev/null || true
    ifconfig "feth$((80 + 2 * s))" destroy 2>/dev/null || true
    ifconfig "feth$((81 + 2 * s))" destroy 2>/dev/null || true
  done
  for l in "${LABELS[@]}"; do rm -f "/Library/LaunchDaemons/$l.plist"; done
  rm -rf "$BIN" "$APP" "$AGENT" "$CD_AGENT" /var/run/usbwifi /var/log/com.usbwifi.wifi.log*
  for p in com.usbwifi.pkg com.usbwifi.pkg.aic8800 com.usbwifi.pkg.rtl8852bu com.usbwifi.pkg.setup com.usbwifi.pkg.clean; do
    pkgutil --forget "$p" >/dev/null 2>&1 || true
  done
  if [[ "$1" == "--clean" ]]; then
    # keep the saved networks: the auto-join profiles (SSID + passphrase) and the dongle-to-slot map that
    # picks which wifi-N.conf a dongle reads. Keychain passwords are never touched
    find "$SUP" -mindepth 1 -maxdepth 1 ! -name wifi.conf ! -name 'wifi-*.conf' ! -name adapters -exec rm -rf {} + 2>/dev/null || true
    echo "cleaned"
  else
    rm -rf "$SUP"
    echo "uninstalled"
  fi
  exit 0
fi

if [[ "${1:-}" != "--setup" ]]; then
  [[ -d "$ROOT/build/USBWifi.app" ]] || { echo "run make first" >&2; exit 1; }
  install -d -m 755 "$BIN" "$SUP/fw"
  install -S -m 755 "$ROOT"/build/{usbwifid,usbwifi_netsvc,libusb-1.0.0.dylib} "$ROOT/scripts/install.sh" "$BIN/"
  rm -rf "$SUP/fw/aic8800D80" "$SUP/fw/rtw89" "$APP"
  for d in aic8800D80 rtw89; do [[ -d "$ROOT/fw/$d" ]] && cp -R "$ROOT/fw/$d" "$SUP/fw/"; done
  cp -R "$ROOT/build/USBWifi.app" "$APP"
fi

# 1.0.x named the service after one vendor; recreate it under the neutral name
networksetup -listallnetworkservices 2>/dev/null | grep -qx 'UGREEN WiFi' && "$BIN/usbwifi_netsvc" remove
"$BIN/usbwifi_netsvc" install

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
# usbwifid runs one worker per plugged dongle (each adds its own "USB Wi-Fi N" service), plus the
# AIC8800D80 firmware loader when $SUP/fw/aic8800D80 is installed
plist com.usbwifi.wifi "$BIN/usbwifid" --daemon
chmod 644 /var/log/com.usbwifi.wifi.log 2>/dev/null || true # readable from the app's "Open Wi-Fi Log"

# keep about one day of log: at boot and hourly, empty it once the last trim (the stamp's mtime) is 24 h old,
# so a Mac that is off at any fixed hour still gets trimmed. In place, not newsyslog's rename: usbwifid's
# stdout stays open on the file in append mode, so it carries on at offset 0
LOG=/var/log/com.usbwifi.wifi.log
cat > "/Library/LaunchDaemons/$LOG_TRIM.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$LOG_TRIM</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string>
<string>[ -e $LOG.trimmed ] || touch $LOG.trimmed; [ -z "\$(find $LOG.trimmed -mmin +1440)" ] || { : > $LOG; touch $LOG.trimmed; }</string></array>
<key>RunAtLoad</key><true/>
<key>StartInterval</key><integer>3600</integer>
</dict></plist>
PL
chmod 644 "/Library/LaunchDaemons/$LOG_TRIM.plist"
launchctl bootstrap system "/Library/LaunchDaemons/$LOG_TRIM.plist"

# Realtek dongles boot as a "driver CD" (0bda:1a2b). Its USB interface sits behind the per-user Removable
# Volumes permission, which a daemon can never hold, so launchd runs the eject in the console user's session
# on each plug-in (as Windows' WifiAutoInstallSrv does on device arrival); the daemon detaches macOS's driver
if [[ -d "$SUP/fw/rtw89" ]]; then
  cat > "$CD_AGENT" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$CD_LABEL</string>
<key>ProgramArguments</key><array><string>$BIN/usbwifid</string><string>cd-eject</string></array>
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

# menu app at login for the console user (same plist the app's "Launch at Login" toggle manages).
# Nobody at the console (pkg pushed at the login window): skip it, the app starts from /Applications later
if [[ "$USER_NAME" == root ]]; then echo "installed (no console user: menu agent skipped)"; exit 0; fi
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

echo "installed. log: /var/log/com.usbwifi.wifi.log"
