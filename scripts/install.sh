#!/usr/bin/env bash
# Install AIC8800D80 support: plug dongle -> firmware loads -> AIC8800Menu offers a network picker
# (or auto-joins the saved one) -> "UGREEN WiFi" network service gets DHCP.
# usage (as root): scripts/install.sh             copy build/ + set up (manual install)
#                  scripts/install.sh --setup     set up only (pkg postinstall: payload already in place)
#                  scripts/install.sh --uninstall
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN=/Library/PrivilegedHelperTools/aic8800-mac
SUP="/Library/Application Support/AIC8800"
APP=/Applications/AIC8800Menu.app
LABELS=(com.aic8800mac.fwload com.aic8800mac.wifi)
MENU_LABEL=com.aic8800mac.menu
[[ $EUID -eq 0 ]] || { echo "need root" >&2; exit 1; }

USER_NAME=$(stat -f %Su /dev/console)
USER_UID=$(id -u "$USER_NAME")
USER_HOME=$(dscl . -read "/Users/$USER_NAME" NFSHomeDirectory | awk '{print $2}')
AGENT="$USER_HOME/Library/LaunchAgents/$MENU_LABEL.plist"

for l in "${LABELS[@]}"; do launchctl bootout "system/$l" 2>/dev/null || true; done
launchctl bootout "gui/$USER_UID/$MENU_LABEL" 2>/dev/null || true
pkill -x AIC8800Menu 2>/dev/null || true

if [[ "${1:-}" == "--uninstall" ]]; then
  [[ -x "$BIN/aic_netsvc" ]] && "$BIN/aic_netsvc" remove || true
  for l in "${LABELS[@]}"; do rm -f "/Library/LaunchDaemons/$l.plist"; done
  rm -rf "$BIN" "$SUP" "$APP" "$AGENT"
  ifconfig feth80 destroy 2>/dev/null || true
  ifconfig feth81 destroy 2>/dev/null || true
  pkgutil --forget com.aic8800mac.pkg >/dev/null 2>&1 || true
  echo "uninstalled"
  exit 0
fi

if [[ "${1:-}" != "--setup" ]]; then
  [[ -d "$ROOT/build/AIC8800Menu.app" ]] || { echo "run make first" >&2; exit 1; }
  install -d -m 755 "$BIN" "$SUP/fw"
  install -m 755 "$ROOT"/build/{aic8800_fwload,aic8800_wifi,aic_netsvc,libusb-1.0.0.dylib} "$BIN/"
  rm -rf "$SUP/fw/aic8800D80" "$APP"
  cp -R "$ROOT/fw/aic8800D80" "$SUP/fw/"
  cp -R "$ROOT/build/AIC8800Menu.app" "$APP"
fi

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
chmod 644 /var/log/com.aic8800mac.wifi.log 2>/dev/null || true # readable from the app's "Open Wi-Fi Log"

# menu app at login for the console user (same plist the app's "Launch at Login" toggle manages)
install -d -o "$USER_NAME" "$USER_HOME/Library/LaunchAgents"
cat > "$AGENT" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$MENU_LABEL</string>
<key>ProgramArguments</key><array><string>$APP/Contents/MacOS/AIC8800Menu</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PL
chown "$USER_NAME" "$AGENT"
launchctl bootstrap "gui/$USER_UID" "$AGENT" || launchctl asuser "$USER_UID" open "$APP"

echo "installed. logs: /var/log/com.aic8800mac.{fwload,wifi}.log"
