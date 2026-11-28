# Installing USB Wifi

## Contents

- [Requirements](#requirements)
- [Install from the release package](#install-from-the-release-package)
- [Upgrading](#upgrading)
- [What gets installed](#what-gets-installed)
- [Settings files](#settings-files)
- [Uninstall](#uninstall)
- [Build from source](#build-from-source)
  - [Run a local build](#run-a-local-build)
- [Troubleshooting](#troubleshooting)
  - [Daemon switches](#daemon-switches)

## Requirements

- An Apple Silicon Mac. The driver has been run on macOS 15 and macOS 27.2.
- A supported USB dongle: AIC8800D80 (such as the UGREEN USB Wi-Fi dongle) or RTL8852BU (such as the TP-Link
  Archer TX20U Nano).
- An administrator account.

## Install from the release package

1. Download `USBWifi.pkg` from the [latest release](https://github.com/huyhandes/aic8800-mac/releases/latest).
   The release notes list its SHA-256, which `shasum -a 256 ~/Downloads/USBWifi.pkg` prints.
2. Install it from Terminal:

   ```sh
   sudo installer -pkg ~/Downloads/USBWifi.pkg -target /
   ```

   This installs both drivers. To pick one, use the Finder instead: double-click the package once (macOS
   blocks it because it is not notarized), open System Settings > Privacy & Security and click Open Anyway.
   On the Installation Type page, tick the driver for your dongle (AIC8800D80, RTL8852BU or both). Tick Clean
   install on the same page to remove every earlier install first, with its settings and logs. Saved networks
   and their Keychain passwords stay.
3. Plug in the dongle. Within a few seconds the driver comes up and the USB Wifi icon appears in the menu bar.
   The menu shows the adapter chip.
4. Click the icon, pick a network and enter the password once. The password is saved in your login Keychain
   and the network is joined on its own from then on.
5. System Settings > Network now shows "USB Wi-Fi" with an IP address.

## Upgrading

Install the newer package over the old one. An upgrade keeps the saved networks. Installing over 1.0.x also
removes the old AIC8800 install. `pkgutil --pkg-info com.usbwifi.pkg` prints the installed version.

## What gets installed

| Path | Contents |
| --- | --- |
| `/Applications/USB Wifi.app` | Menu bar app |
| `/Library/PrivilegedHelperTools/usbwifi/` | Daemon, network service helper, bundled libusb, `install.sh` |
| `/Library/Application Support/USB Wifi/` | Firmware (`fw/aic8800D80`, `fw/rtw89`), licenses, saved networks and the [settings files](#settings-files) |
| `/Library/LaunchDaemons/com.usbwifi.wifi.plist` | Starts the daemon when a dongle is plugged in |
| `/Library/LaunchDaemons/com.usbwifi.logtrim.plist` | Empties the log once a day |
| `/Library/LaunchAgents/com.usbwifi.cdswitch.plist` | Switches a plugged RTL8852BU out of driver-CD mode (RTL8852BU driver only) |
| `~/Library/LaunchAgents/com.usbwifi.menu.plist` | Starts the menu app at login |

## Settings files

All live in `/Library/Application Support/USB Wifi/`. The menu app writes them, so editing by hand is only
needed on a Mac without a desktop session. The first dongle (slot 0) uses the plain name, dongle N uses the
name with `-N` (`band-1`, `wifi-1.conf` and so on).

| File | Values | Meaning |
| --- | --- | --- |
| `wifi.conf` | SSID and passphrase | The saved network. Root only (mode 0600). |
| `adapters` | One MAC address per line | Which dongle has which slot. Line N is slot N. |
| `band` | `auto`, `5`, `2.4` | Preferred band. `auto` takes 5 GHz unless it is more than 15 dB weaker or below -75 dBm. |
| `roam` | `VeryHigh`, `High`, `Middle`, `Low`, `VeryLow`, `Disable` | Roaming Sensitivity. Default `VeryHigh`. |
| `powersave` | `on`, `off` | Power Saving. Off by default for lower latency. |
| `macrandom` | `on`, `off` | MAC Randomization per network (RTL8852BU). On unless the file says `off`. |
| `country` | Two letters, such as `VN` | RTL8852BU TX power table. Default `US`, because the Realtek VN/ETSI table holds 5 GHz channels 112 to 128 to 7 dBm. |
| `chans` | Written by the daemon | Channels where the saved network was last seen, so a reconnect scans only those. |

## Uninstall

```sh
sudo /Library/PrivilegedHelperTools/usbwifi/install.sh --uninstall
```

`--clean` in place of `--uninstall` removes the same files but keeps the saved networks (`wifi.conf`,
`wifi-N.conf`, `adapters`) and the Keychain passwords.

## Build from source

You need the Xcode command line tools and Homebrew. The firmware is not in this repository: the AIC8800D80
firmware comes from the Linux driver and the RTL8852BU firmware from linux-firmware.

```sh
brew install libusb pkg-config
git clone https://github.com/huyhandes/aic8800-mac && cd aic8800-mac

git clone --depth 1 https://github.com/asanrivas/aic8800-linux-driver /tmp/aic-linux
mkdir -p fw && cp -R /tmp/aic-linux/fw/aic8800D80 fw/

git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git /tmp/lfw
mkdir -p fw/rtw89 && cp /tmp/lfw/rtw89/rtw8852b_fw-2.bin /tmp/lfw/LICENSES/LICENCE.rtlwifi_firmware.txt fw/rtw89/

make pkg            # builds build/USBWifi.pkg
sudo installer -pkg build/USBWifi.pkg -target /
```

`make check` needs no root. It runs the unit tests (WPA2 handshake, BlockAck reorder, AIC8800 framing, driver
contract, lkpi kernel and mac80211), then brings up a free dongle and scans. An AIC8800D80 is used only if its
firmware already runs. An RTL8852BU needs the RTL8852BU driver installed, or `LKPI_FW_DIR=<dir holding rtw89/>`.
The scan step fails while the installed daemon holds the dongles.

### Run a local build

- `sudo scripts/install.sh` installs straight from `build/`, without a package.
- `sudo scripts/usbwifi-up.sh <SSID>` runs the driver in the foreground for debugging. It asks for the
  passphrase. Do not run it while the daemon is installed, because both claim the USB interface.

## Troubleshooting

- The log is `/var/log/com.usbwifi.wifi.log`. AIC8800D80 firmware loader lines start with `[fwload]`.
- `scripts/bench-connect.sh [rounds]` measures the reconnect time and needs no root. Set `SLOT=N` to test
  another dongle.
- `usbwifid status|scan|connect` and `scripts/usbwifi-up.sh` talk to slot 0 only. Use the menu app for other
  dongles.
- A TX20U Nano that stays a "DISK" in System Information is still in driver-CD mode. The switch to Wi-Fi runs
  in your login session, so it needs a user logged in to the desktop. At the login window or on a headless
  Mac, unplug and replug after logging in. `usbwifid cd-eject` (as your user, not root) does the switch by
  hand.
- The dongle becomes the default route when its service is first in the service order. To put another service
  first, reorder the services in System Settings > Network.
- Power save is off by default, so the dongle draws a little more power and runs warmer. Turn on Power Saving
  per dongle in the menu.

### Daemon switches

The daemon reads these from the `EnvironmentVariables` of `/Library/LaunchDaemons/com.usbwifi.wifi.plist`.
Set any value, such as `1`, then reload the daemon. An upgrade rewrites that plist, so set them again after
one. All but `AICD_ALWAYS_SCAN` apply to the AIC8800D80 only.

| Variable | Effect |
| --- | --- |
| `AICD_NO_RX_AGG` | Turns off RX aggregation, for a link that is unstable under load |
| `AICD_NO_VHT` | Does not offer 802.11ac (5 GHz falls back to HT40) |
| `AICD_NO_HE` | Does not offer 802.11ax |
| `AICD_ALWAYS_SCAN` | Always scans before reconnecting, instead of reusing the last network |
