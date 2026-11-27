# Install

Requirements:

- an Apple Silicon Mac with macOS 15 (tested on 15.x / Darwin 24);
- an AIC8800D80 USB dongle, such as the UGREEN USB Wi-Fi dongle;
- an administrator account.

## From the release package

1. Download `AIC8800-mac.pkg` from the [latest release](https://github.com/huyhandes/aic8800-mac/releases/latest).
2. The package is not notarized, so macOS blocks a double-click. Either run
   `sudo installer -pkg AIC8800-mac.pkg -target /` in Terminal, or double-click
   once, then open System Settings → Privacy & Security and click **Open Anyway**.
3. Plug in the dongle. Within a few seconds the firmware loads and the
   **AIC8800Menu** icon appears in the menu bar.
4. Click the icon, pick a network and enter the password once. The password is
   saved in your login Keychain, and the network is joined automatically next time.
5. System Settings → Network now shows **UGREEN WiFi** with an IP address.

Installing a newer package over 1.0.x upgrades in place and keeps the saved
network. Check the installed version with `pkgutil --pkg-info com.aic8800mac.pkg`.

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
- The daemon reads these switches from the `EnvironmentVariables` of
  `/Library/LaunchDaemons/com.aic8800mac.wifi.plist` (set any value, e.g. `1`,
  then reload the daemon). Use them if a network misbehaves:

  | Variable | Effect |
  |---|---|
  | `AICD_NO_RX_AGG` | turn off RX aggregation, if the link is unstable under load |
  | `AICD_NO_VHT` | do not offer 802.11ac (5 GHz falls back to HT40) |
  | `AICD_NO_HE` | do not offer 802.11ax |
  | `AICD_PS` | turn power save back on: less power, higher and spikier latency |
  | `AICD_ALWAYS_SCAN` | always scan before reconnecting, instead of reusing the last network |

- Since 1.0.2, power save is off by default for low latency, so the dongle draws
  a little more power while connected.
- The dongle becomes the default route when it is first in the service order.
  If you want another service first, reorder services in System Settings → Network.
