# aic8800-mac

Userspace macOS driver for USB Wi-Fi dongles built on the **AIC8800D80** chip
(tested with a UGREEN USB Wi-Fi dongle, USB `a69c:5723` → `368b:8d85`) on Apple Silicon.
It needs no kernel extension. The dongle is driven over libusb and shows up as
a normal network service, **"UGREEN WiFi"** (`feth80`), in System Settings →
Network.

## Features

- WPA2-PSK and open networks on 2.4 and 5 GHz. It prefers 5 GHz when the signal is good enough.
- Menu bar app (AIC8800Menu) to scan, pick and forget networks. Passwords are stored in the login Keychain.
- A wrong password is reported as "Wrong password" and is not retried forever.
- Starts automatically when the dongle is plugged in: launchd loads the firmware and joins the saved network.
- macOS (configd) handles DHCP and IPv6. The link state follows Wi-Fi, so DHCP runs again after a network change.
- 802.11ax at 80 MHz on 5 GHz, with TX/RX A-MPDU and BlockAck reorder. Power save is off for low latency.
- Reconnects to the saved network in about 0.5 s (see [Performance](#performance)).
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
daemon: `AICD_NO_VHT`, `AICD_NO_HE`, `AICD_PS` (power save back on),
`AICD_ALWAYS_SCAN`.

## How it works

```
dongle ──USB (libusb)── aic8800_wifi daemon ──BPF── feth81 ⇄ feth80 ── macOS network stack
```

- `aic8800_fwload` pushes the firmware when the dongle appears in its mass-storage mode.
- `aic8800_wifi --daemon` runs the LMAC, the WPA2 4-way handshake and the data path. It bridges Ethernet frames to a `feth` pair.
- `aic_netsvc` creates the "UGREEN WiFi" network service.

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
- The `feth` + BPF approach follows how tethering tools such as TetherKit expose
  userspace network devices on macOS.

## License

BSD-3-Clause, see [LICENSE](LICENSE). Third-party parts keep their own
licenses: `third_party/yokitea/LICENSE`, libusb (LGPL), firmware (AICSemi).

This project is not affiliated with UGREEN or AICSemi.
