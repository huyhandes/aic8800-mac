# Install

Requirements:

- an Apple Silicon Mac with macOS 15 (tested on 15.x / Darwin 24);
- a supported USB dongle: AIC8800D80 (such as the UGREEN USB Wi-Fi dongle) or RTL8852BU (such as the TP-Link Archer TX20U Nano);
- an administrator account.

## From the release package

1. Download `USBWifi.pkg` from the [latest release](https://github.com/huyhandes/aic8800-mac/releases/latest).
2. The package is not notarized, so macOS blocks a double-click. Double-click
   once, then open System Settings → Privacy & Security and click **Open Anyway**.
   On the **Installation Type** page, tick the driver for your dongle
   (AIC8800D80, RTL8852BU, or both). From Terminal,
   `sudo installer -pkg USBWifi.pkg -target /` installs both drivers.
3. Plug in the dongle. Within a few seconds the driver comes up and the
   **USB Wifi** icon appears in the menu bar. The menu shows the adapter chip.
4. Click the icon, pick a network and enter the password once. The password is
   saved in your login Keychain, and the network is joined automatically next time.
5. System Settings → Network now shows **USB Wi-Fi** with an IP address.

Installing a newer package over 1.0.x upgrades in place and keeps the saved
network. Check the installed version with `pkgutil --pkg-info com.aic8800mac.pkg`.

What gets installed:

| Path | What |
|---|---|
| `/Applications/USB Wifi.app` | menu bar app |
| `/Library/PrivilegedHelperTools/aic8800-mac/` | daemons, bundled libusb, `install.sh` |
| `/Library/Application Support/AIC8800/` | firmware (`fw/aic8800D80`, `fw/rtw89`), licenses, saved profile (`wifi.conf`, root 0600) |
| `/Library/LaunchDaemons/com.aic8800mac.{fwload,wifi}.plist` | auto-start on plug (`fwload` only with the AIC8800D80 driver) |
| `~/Library/LaunchAgents/com.aic8800mac.menu.plist` | menu app at login |

## Uninstall

```sh
sudo /Library/PrivilegedHelperTools/aic8800-mac/install.sh --uninstall
```

## Build from source

```sh
brew install libusb pkg-config
git clone https://github.com/huyhandes/aic8800-mac && cd aic8800-mac
# the firmware is not in this repo; AIC8800D80 from the Linux driver, RTL8852BU from linux-firmware
git clone --depth 1 https://github.com/asanrivas/aic8800-linux-driver /tmp/aic-linux
mkdir -p fw && cp -R /tmp/aic-linux/fw/aic8800D80 fw/
git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git /tmp/lfw
mkdir -p fw/rtw89 && cp /tmp/lfw/rtw89/rtw8852b_fw-2.bin /tmp/lfw/LICENSES/LICENCE.rtlwifi_firmware.txt fw/rtw89/
make pkg            # -> build/USBWifi.pkg
sudo installer -pkg build/USBWifi.pkg -target /
```

- `make check` needs no root. It runs the WPA2 handshake self-test, then brings up the
  dongle and scans (an AIC8800D80 only if its firmware is already running; an RTL8852BU
  needs the RTL8852BU driver installed, or `LKPI_FW_DIR=<dir holding rtw89/>`).
- `sudo scripts/install.sh` installs straight from `build/`, without a package.
- `sudo scripts/aic-up.sh <SSID>` runs the driver in the foreground for
  debugging. Do not run it while the daemon is installed, because both claim
  the USB interface.

## Troubleshooting

- Logs are in `/var/log/com.aic8800mac.fwload.log` and `/var/log/com.aic8800mac.wifi.log`.
- `scripts/bench-connect.sh [rounds]` measures reconnect time and needs no root.
- The daemon reads these switches from the `EnvironmentVariables` of
  `/Library/LaunchDaemons/com.aic8800mac.wifi.plist` (set any value, e.g. `1`,
  then reload the daemon). Use them if a network misbehaves. All but `AICD_ALWAYS_SCAN` apply to the
  AIC8800D80 only:

  | Variable | Effect |
  |---|---|
  | `AICD_NO_RX_AGG` | turn off RX aggregation, if the link is unstable under load |
  | `AICD_NO_VHT` | do not offer 802.11ac (5 GHz falls back to HT40) |
  | `AICD_NO_HE` | do not offer 802.11ax |
  | `AICD_PS` | turn power save back on: less power, higher and spikier latency |
  | `AICD_ALWAYS_SCAN` | always scan before reconnecting, instead of reusing the last network |

- Since 1.0.2, power save is off by default for low latency, so the dongle draws
  a little more power while connected.
- A TX20U Nano that stays a "DISK" in System Information is still in driver-CD mode. The switch to
  Wi-Fi runs in your login session, so it needs a user logged in to the desktop; at the login window
  or on a headless Mac, unplug and replug after logging in. `aic8800_wifi cd-eject` (as your user, not
  root) does the switch by hand.
- The dongle becomes the default route when it is first in the service order.
  If you want another service first, reorder services in System Settings → Network.
