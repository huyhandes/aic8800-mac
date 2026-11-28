# Apple Silicon (macos) Unified USB Wifi Driver

Userspace macOS driver for USB Wi-Fi dongles on Apple Silicon. Supported chips:

- **AIC8800D80**, tested with a UGREEN USB Wi-Fi dongle (USB `a69c:5723` → `368b:8d85`);
- **Realtek RTL8852BU**, tested with a TP-Link Archer TX20U Nano (USB `0bda:1a2b` → `35bc:0108`).

It needs no kernel extension. The dongle is driven over libusb and shows up as
a normal network service, **"USB Wi-Fi"** (`feth80`), in System Settings →
Network.

## Features

- WPA2-PSK and open networks on 2.4 and 5 GHz (WPA2/WPA3 transition networks join over WPA2). It prefers 5 GHz when the signal is good enough.
- Menu bar app (**USB Wifi**) that shows the adapter chip and lets you scan, pick and forget networks. Passwords are stored in the login Keychain.
- Several dongles at once, each on its own network. Every dongle gets its own network service
  ("USB Wi-Fi", "USB Wi-Fi 2", ...) and its own section in the menu. Routing between them is left to you
  (service order in System Settings, or `route`).
- One installer: pick the AIC8800D80 driver, the RTL8852BU driver, or both.
- A wrong password is reported as "Wrong password" and is not retried forever.
- Starts automatically when the dongle is plugged in: launchd loads the firmware and joins the saved network.
- macOS (configd) handles DHCP and IPv6. The link state follows Wi-Fi, so DHCP runs again after a network change.
- AIC8800D80: 802.11ax at 80 MHz on 5 GHz, with TX/RX A-MPDU and BlockAck reorder. Power save is off for low latency.
  Reconnects to the saved network in about 0.5 s (see [Performance](#performance)).
- Drops the Wi-Fi link on system sleep, so the dongle does not keep waking the Mac.

See [INSTALL.md](INSTALL.md) to install or build.

## Performance

Measured with v1.0.2 on an Apple Silicon MacBook, 5 GHz 80 MHz 802.11ax AP. The
built-in Wi-Fi was on the same AP. LAN numbers are `iperf3` to another host on
the same network.

| | Dongle (`feth80`) | Built-in Wi-Fi (`en0`) |
|---|---|---|
| Ping to the AP (idle) | ~2 ms | ~9 ms |
| Reconnect → IP / first ping | 0.48–0.53 s / 0.53–0.59 s | — / 1.4–1.6 s (radio off → on) |
| LAN TCP upload / download | ~250 / ~240 Mbit/s | 457 / 317 Mbit/s |
| LAN UDP, both directions | ~310 Mbit/s | not measured |
| Internet, `networkQuality` up / down | 250 / 234 Mbit/s | 240 / 232 Mbit/s |

- Throughput is capped by USB 2.0 (480 Mbit/s raw, about 310 Mbit/s of
  payload here) and by the dongle having one spatial stream. Most built-in
  Wi-Fi has two.
- About 390 ms of each reconnect is the firmware's own wait between the connect
  request and the association result. The driver cannot shorten it.
- The 1.4–1.6 s for the built-in Wi-Fi includes powering the radio back on, so
  it is not an exact like-for-like comparison.

Each optimization can be turned off with an environment variable on the
daemon: `AICD_NO_VHT`, `AICD_NO_HE`, `AICD_ALWAYS_SCAN`. Power save is off by
default and has a per-dongle Power Saving toggle in the menu.

## How it works

```
dongle ──USB (libusb)── usbwifid daemon ──BPF── feth81 ⇄ feth80 ── macOS network stack
```

- `usbwifid fwload` pushes the AIC8800 firmware when that dongle appears in its mass-storage mode. The daemon keeps it running as a child process when the AIC8800D80 driver is installed.
- `usbwifid --daemon` runs the WPA2 4-way handshake and the data path for either chip. It bridges Ethernet frames to a `feth` pair.
  - AIC8800D80: the dongle firmware runs the MAC (LMAC); the daemon talks its USB message protocol.
  - RTL8852BU: the upstream Linux **rtw89** driver (`third_party/rtw89/`, unmodified) is compiled against
    `src/lkpi/`, a small userspace stand-in for the Linux kernel, USB and mac80211 APIs it uses, plus a
    station MLME (`src/lkpi/mlme.c`: scan, auth/assoc, keys, CCMP replay check, A-MPDU/BlockAck).
    The dongle first shows up as a Realtek "driver CD" (`0bda:1a2b`). Windows' WifiAutoInstallSrv sends it a
    SCSI eject on every plug; here the daemon detaches macOS's storage driver, and a per-user LaunchAgent
    (`com.usbwifi.cdswitch`, started by launchd on plug-in) sends the same eject, because macOS gives
    access to removable-media interfaces only to the logged-in user. Wi-Fi mode follows in about 2 s.
- `usbwifi_netsvc` creates the "USB Wi-Fi" network service.

### Several dongles

`usbwifid --daemon` is a supervisor. It runs one `usbwifid --worker` process per dongle, plus one idle
worker that waits for the next dongle. macOS gives a USB interface to one process at a time, so each worker
binds the first dongle that no other worker holds. A dongle's slot N is its line in
`/Library/Application Support/USB Wifi/adapters`, keyed by MAC, so a dongle keeps its slot across replugs:

| | slot 0 | slot N |
|---|---|---|
| network service | USB Wi-Fi | USB Wi-Fi N+1 |
| interface | `feth80` (peer `feth81`) | `feth(80+2N)` (peer `feth(81+2N)`) |
| control socket | `/var/run/usbwifi/0.sock` | `/var/run/usbwifi/N.sock` |
| saved network | `wifi.conf` | `wifi-N.conf` |

### Adding a chip driver

`src/wifi_drv.h` is the contract between the chip-independent station core (`src/usbwifi_core.c`: scan list,
connection state, WPA2 EAPOL, the `feth`/BPF side, slots) and a chip driver (`src/drv_aic8800.c`,
`src/drv_rtw89.c`). To add a chip, implement `struct wifi_drv` (open, scan, connect, disconnect, add_key,
set_authorized, tx) in `src/drv_<chip>.c`. Report results through `struct wifi_drv_events`, then add the
driver to `wifi_drivers[]` in `usbwifi_core.c` and to `CORE_SRC` in the Makefile.

## Credits

- [yokitea/aic8800-macos](https://github.com/yokitea/aic8800-macos) (BSD-3-Clause):
  the AIC8800WiFi kext, firmware loader, WPA2 code and menu app that this port
  is built on. They are vendored in `third_party/yokitea/` with their license.
- [asanrivas/aic8800-linux-driver](https://github.com/asanrivas/aic8800-linux-driver)
  (Linux driver by goecho, based on AICSemi's driver): the reference for the USB
  protocol and RX reorder, and the source of the `aic8800D80` firmware files.
- [libusb](https://libusb.info) (LGPL-2.1-or-later) provides USB access. It is
  bundled as a dynamic library in the release package.
- AICSemi wrote the AIC8800 firmware. It is proprietary and redistributed unmodified.
- [Linux rtw89](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/realtek/rtw89)
  by Realtek (GPL-2.0 OR BSD-3-Clause, used here under BSD-3-Clause) drives the RTL8852BU, and
  `rtw89/rtw8852b_fw-2.bin` comes from [linux-firmware](https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git)
  (Realtek's redistributable firmware licence, shipped as `LICENCE.rtlwifi_firmware.txt`).
- The `feth` + BPF approach follows how tethering tools such as TetherKit expose
  userspace network devices on macOS.

## License

BSD-3-Clause, see [LICENSE](LICENSE). Third-party parts keep their own
licenses: `third_party/yokitea/LICENSE`, `third_party/rtw89/COPYING`, libusb (LGPL), firmware (AICSemi, Realtek).

This project is not affiliated with UGREEN, AICSemi, TP-Link or Realtek.
