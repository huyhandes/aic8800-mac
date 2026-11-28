# USB Wifi for Apple Silicon Macs

[![Release](https://img.shields.io/github/v/release/huyhandes/aic8800-mac)](https://github.com/huyhandes/aic8800-mac/releases/latest)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
![Platform: macOS on Apple Silicon](https://img.shields.io/badge/platform-macOS%20%7C%20Apple%20Silicon-lightgrey)

A userspace macOS driver for USB Wi-Fi dongles. It needs no kernel extension: the daemon drives the dongle
over libusb and macOS sees a normal network service called "USB Wi-Fi" in System Settings > Network.
A menu bar app picks networks and stores their passwords in the login Keychain.

## Contents

- [Supported hardware](#supported-hardware)
- [Features](#features)
- [Quick start](#quick-start)
- [Performance](#performance)
- [How it works](#how-it-works)
  - [Several dongles](#several-dongles)
  - [Adding a chip driver](#adding-a-chip-driver)
- [Known issues](#known-issues)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

## Supported hardware

- AIC8800D80, tested with a UGREEN USB Wi-Fi dongle. USB ID `a69c:5723` in its storage mode, `368b:8d85` once the
  firmware runs.
- Realtek RTL8852BU, tested with a TP-Link Archer TX20U Nano. USB ID `0bda:1a2b` in its "driver CD" mode,
  `35bc:0108` in Wi-Fi mode.

Other dongles with the same chips and USB IDs should work but are untested. The host is an Apple Silicon Mac;
the driver has been run on macOS 15 and macOS 27.2.

## Features

- Open, WPA2-PSK and WPA2/WPA3 transition networks on 2.4 and 5 GHz. Both chips use 802.11ax on 5 GHz.
- RTL8852BU only: WPA3-SAE (with H2E), PMF, FT-PSK, 802.11k/v roaming and per-network MAC randomization.
  The AIC8800D80 joins WPA2/WPA3 transition networks over WPA2.
- Starts on plug-in. launchd starts the daemon, which loads the firmware and joins the saved network.
- Several dongles at once, each with its own network service ("USB Wi-Fi", "USB Wi-Fi 2", ...) and its own
  section in the menu.
- Menu bar app: scan, join and forget networks, and per dongle a Preferred Band (Auto, 5 GHz, 2.4 GHz),
  Roaming Sensitivity, Power Saving and MAC Randomization setting.
- macOS (configd) runs DHCP and IPv6. The link follows the Wi-Fi state, so DHCP runs again after a network
  change.
- A wrong password shows as "Wrong password" and is not retried forever.
- The Wi-Fi link drops on system sleep, so the dongle does not keep waking the Mac.
- One installer package. Pick the AIC8800D80 driver, the RTL8852BU driver or both.

## Quick start

1. Download `USBWifi.pkg` from the [latest release](https://github.com/huyhandes/aic8800-mac/releases/latest).
2. Install it: `sudo installer -pkg ~/Downloads/USBWifi.pkg -target /`. The package is not notarized, so a
   double-click needs Open Anyway in System Settings > Privacy & Security.
3. Plug in the dongle, click the USB Wifi icon in the menu bar and pick a network.

[INSTALL.md](INSTALL.md) has the full steps, what gets installed, uninstalling, building from source and
troubleshooting.

## Performance

Measured on 2026-11-28 with v1.1.1 on an Apple Silicon MacBook, both dongles on the same 802.11ax AP
(5 GHz at 5240 MHz with 80 MHz, 2.4 GHz at 2412 MHz). Numbers are `networkQuality -s` to the internet, two
runs each, in Mbit/s.

| Dongle | Band | Upload | Download |
| --- | --- | --- | --- |
| AIC8800D80 | 5 GHz | 257 to 284 | 198 to 243 |
| AIC8800D80 | 2.4 GHz | 85 to 90 | 63 to 74 |
| RTL8852BU | 5 GHz | 104 to 113 | 152 to 154 |
| RTL8852BU | 2.4 GHz | 34 to 35 | 97 to 99 |

Connect times from the daemon log on the same day:

- AIC8800D80: plug-in to a DHCP lease in about 8 s, most of it the firmware upload and the dongle
  re-enumerating.
- RTL8852BU: about 4.4 s from the dongle appearing in Wi-Fi mode to a DHCP lease. The switch out of
  driver-CD mode adds about 2 s before that.
- Reconnecting the AIC8800D80 to the saved network (DISCONNECT, then RECONNECT) took about 0.5 s to an IP
  address with v1.0.2. `scripts/bench-connect.sh` measures it.

The AIC8800D80 has one spatial stream and USB 2.0 caps both dongles at 480 Mbit/s raw (about 310 Mbit/s of
payload). With v1.0.2 the AIC8800D80 reached about 250 Mbit/s upload and 240 Mbit/s download in LAN `iperf3`
tests, and a 2 ms ping to the AP against 9 ms for the built-in Wi-Fi.

## How it works

```text
dongle --USB (libusb)-- usbwifid daemon --BPF-- feth81 <-> feth80 -- macOS network stack
```

- `usbwifid fwload` pushes the AIC8800D80 firmware when that dongle appears in its mass-storage mode. The
  daemon keeps it running as a child process when the AIC8800D80 driver is installed.
- `usbwifid --daemon` runs the WPA2 4-way handshake and the data path for both chips, and bridges Ethernet
  frames to a `feth` pair.
  - AIC8800D80: the dongle firmware runs the MAC (LMAC). The daemon speaks its USB message protocol.
  - RTL8852BU: the upstream Linux rtw89 driver (`third_party/rtw89/`, unmodified) is compiled against
    `src/lkpi/`, a small userspace stand-in for the Linux kernel, USB and mac80211 APIs it uses. On top of it
    sits a station MLME (`src/lkpi/mlme.c`: scan, auth/assoc, keys, CCMP replay check, A-MPDU and BlockAck).
- The RTL8852BU first shows up as a Realtek "driver CD" (`0bda:1a2b`). On Windows, WifiAutoInstallSrv sends it a
  SCSI eject on every plug. Here the daemon detaches the macOS storage driver and a per-user LaunchAgent
  (`com.usbwifi.cdswitch`, started by launchd on plug-in) sends the same eject, because macOS gives access to
  removable-media interfaces only to the logged-in user. Wi-Fi mode follows in about 2 s.
- `usbwifi_netsvc` creates the "USB Wi-Fi" network service.

### Several dongles

`usbwifid --daemon` is a supervisor. It runs one `usbwifid --worker` process per dongle plus one idle worker
that waits for the next dongle. macOS gives a USB interface to one process at a time, so each worker binds the
first dongle no other worker holds. A dongle's slot N is its line in
`/Library/Application Support/USB Wifi/adapters`, keyed by MAC address, so a dongle keeps its slot across
replugs.

| | Slot 0 | Slot N |
| --- | --- | --- |
| Network service | USB Wi-Fi | USB Wi-Fi N+1 |
| Interface | `feth80` (peer `feth81`) | `feth(80+2N)` (peer `feth(81+2N)`) |
| Control socket | `/var/run/usbwifi/0.sock` | `/var/run/usbwifi/N.sock` |
| Saved network | `wifi.conf` | `wifi-N.conf` |

Routing between dongles is left to you: the service order in System Settings > Network, or `route`.

### Adding a chip driver

`src/wifi_drv.h` is the contract between the chip-independent station core (`src/usbwifi_core.c`: scan list,
connection state, WPA2 EAPOL, the `feth` and BPF side, slots) and a chip driver (`src/aic8800/drv_aic8800.c`,
`src/rtw89/drv_rtw89.c`).

To add a chip:

1. Implement `struct wifi_drv` (open, scan, connect, disconnect, add_key, set_authorized, tx) in
   `src/<chip>/drv_<chip>.c` and report results through `struct wifi_drv_events`.
2. Add the driver to `wifi_drivers[]` in `src/usbwifi_core.c` and to `CORE_SRC` in the Makefile.

A new driver can reuse the chip-independent parts as they are: the scan list and IE parsers
(`src/wifi_ctl.h`), the WPA2 handshake and PMF keys (`src/wpa2.h`), WPA3-SAE (`src/wpa3.h`), FT-PSK roaming
(`src/ft.h`) and the BlockAck reorder window (`src/rx_reord.h`). SAE and FT need the optional `ft_connect` op.

## Known issues

- The RTL8852BU reaches about 100 Mbit/s upload on 5 GHz, less than the single-stream AIC8800D80. rtw89 sends
  one MPDU per USB transfer and the dongle takes about 6500 transfers a second, so upload depends on how many
  packets fit in one A-MSDU. Builds before 1.1.0 measured about 67 Mbit/s on the same AP.
- The AIC8800D80 does not join WPA3-only networks.
- The package is not notarized, so macOS asks before installing it.
- `usbwifid status|scan|connect` and `scripts/usbwifi-up.sh` talk to slot 0 only. Use the menu app for other
  dongles.

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/huyhandes/aic8800-mac/issues).
A report is easiest to act on with the chip, the macOS version, the AP's security mode and band, and the
lines around the problem from `/var/log/com.usbwifi.wifi.log`.

To work on the code:

```sh
brew install libusb pkg-config
make          # builds build/usbwifid, the network service helper and the menu app
make check    # unit tests, then a scan with a free dongle (no root needed)
```

`make check` runs the WPA2, BlockAck reorder, AIC8800 framing, driver contract, lkpi kernel and mac80211
tests before the scan. The scan step fails while the installed daemon holds the dongles, which is expected.
[INSTALL.md](INSTALL.md#build-from-source) has the firmware setup and the steps to run a local build.

New code follows the style of the file around it. A change to a parser, the handshake or the reorder window
comes with a test in `tests/`.

## Credits

- [yokitea/aic8800-macos](https://github.com/yokitea/aic8800-macos) (BSD-3-Clause): the AIC8800WiFi kext,
  firmware loader, WPA2 code and menu app this port started from. They are vendored in `third_party/yokitea/`
  with their license. The chip-independent headers moved to `src/wifi_ctl.h`, `src/wpa2.h` and
  `src/rx_reord.h`.
- [asanrivas/aic8800-linux-driver](https://github.com/asanrivas/aic8800-linux-driver) (Linux driver by goecho,
  based on the AICSemi driver): the reference for the USB protocol and RX reorder, and the source of the
  `aic8800D80` firmware files.
- [Linux rtw89](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/realtek/rtw89)
  by Realtek (GPL-2.0 OR BSD-3-Clause, used here under BSD-3-Clause) drives the RTL8852BU.
  `rtw89/rtw8852b_fw-2.bin` comes from
  [linux-firmware](https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git) under the
  Realtek firmware licence, shipped as `LICENCE.rtlwifi_firmware.txt`.
- [libusb](https://libusb.info) (LGPL-2.1-or-later) gives USB access. The release package bundles it as a
  dynamic library.
- AICSemi wrote the AIC8800 firmware. It is proprietary and redistributed unmodified.
- The `feth` and BPF approach follows how tethering tools such as TetherKit expose userspace network devices
  on macOS.

## License

BSD-3-Clause, see [LICENSE](LICENSE). Third-party parts keep their own licenses:
`third_party/yokitea/LICENSE`, `third_party/rtw89/COPYING`, libusb (LGPL), and the AICSemi and Realtek
firmware.

This project is not affiliated with UGREEN, AICSemi, TP-Link or Realtek.
