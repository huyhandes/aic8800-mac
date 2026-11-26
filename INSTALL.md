# Install

Requirements:

- an Apple Silicon Mac with macOS 15 (tested on 15.x / Darwin 24);
- an AIC8800D80 USB dongle, such as the UGREEN USB Wi-Fi dongle;
- an administrator account.

## From the release package

1. Download `AIC8800-mac.pkg` from the [latest release](https://github.com/huyhandes/aic8800-mac/releases/latest).
2. The package is not notarized. Right-click it and choose Open, or run
   `sudo installer -pkg AIC8800-mac.pkg -target /`.
3. Plug in the dongle. Within a few seconds the firmware loads and the
   **AIC8800Menu** icon appears in the menu bar.
4. Click the icon, pick a network and enter the password once. The password is
   saved in your login Keychain, and the network is joined automatically next time.
5. System Settings → Network now shows **UGREEN WiFi** with an IP address.

What gets installed:

| Path | What |
|---|---|
| `/Applications/AIC8800Menu.app` | menu bar app |
| `/Library/PrivilegedHelperTools/aic8800-mac/` | daemons, bundled libusb, `install.sh` |
| `/Library/Application Support/AIC8800/` | firmware, licenses, saved profile (`wifi.conf`, root 0600) |
| `/Library/LaunchDaemons/com.aic8800mac.{fwload,wifi}.plist` | auto-start on plug |
| `~/Library/LaunchAgents/com.aic8800mac.menu.plist` | menu app at login |

## Uninstall

```sh
sudo /Library/PrivilegedHelperTools/aic8800-mac/install.sh --uninstall
```

## Build from source

```sh
brew install libusb pkg-config
git clone https://github.com/huyhandes/aic8800-mac && cd aic8800-mac
# the firmware is not in this repo; take it from the Linux driver
git clone --depth 1 https://github.com/asanrivas/aic8800-linux-driver /tmp/aic-linux
mkdir -p fw && cp -R /tmp/aic-linux/fw/aic8800D80 fw/
make pkg            # -> build/AIC8800-mac.pkg
sudo installer -pkg build/AIC8800-mac.pkg -target /
```

- `make check` needs no root. It brings up the LMAC and scans, but only with a
  dongle whose firmware is already running.
- `sudo scripts/install.sh` installs straight from `build/`, without a package.
- `sudo scripts/aic-up.sh <SSID>` runs the driver in the foreground for
  debugging. Do not run it while the daemon is installed, because both claim
  the USB interface.

## Troubleshooting

- Logs are in `/var/log/com.aic8800mac.fwload.log` and `/var/log/com.aic8800mac.wifi.log`.
- `scripts/bench-connect.sh [rounds]` measures reconnect time and needs no root.
- If the link is unstable under load, turn off RX aggregation: set
  `AICD_NO_RX_AGG=1` in the `EnvironmentVariables` of
  `/Library/LaunchDaemons/com.aic8800mac.wifi.plist`, then reload the daemon.
- The dongle becomes the default route when it is first in the service order.
  If you want another service first, reorder services in System Settings → Network.
