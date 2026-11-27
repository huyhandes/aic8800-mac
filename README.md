# aic8800-mac

Userspace macOS driver for USB Wi-Fi dongles on Apple Silicon. Supported chips:

- **AIC8800D80**, tested with a UGREEN USB Wi-Fi dongle (USB `a69c:5723` → `368b:8d85`);
- **Realtek RTL8852BU**, tested with a TP-Link Archer TX20U Nano (USB `0bda:1a2b` → `35bc:0108`).

It needs no kernel extension. The dongle is driven over libusb and shows up as
a normal network service, **"USB Wi-Fi"** (`feth80`), in System Settings →
Network.

## Features

- WPA2-PSK and open networks on 2.4 and 5 GHz (WPA2/WPA3 transition networks join over WPA2). It prefers 5 GHz when the signal is good enough.
- Menu bar app (**USB Wifi**) that shows the adapter chip and lets you scan, pick and forget networks. Passwords are stored in the login Keychain.
- One installer: pick the AIC8800D80 driver, the RTL8852BU driver, or both.
- A wrong password is reported as "Wrong password" and is not retried forever.
- Starts automatically when the dongle is plugged in: launchd loads the firmware and joins the saved network.
- macOS (configd) handles DHCP and IPv6. The link state follows Wi-Fi, so DHCP runs again after a network change.
- AIC8800D80: reconnects and gets an IP in about 1.3 s. Download speed is about 65–70 Mbit/s with RX A-MPDU and BlockAck reorder.
- Drops the Wi-Fi link on system sleep, so the dongle does not keep waking the Mac.

See [INSTALL.md](INSTALL.md) to install or build.

## How it works

```
dongle ──USB (libusb)── aic8800_wifi daemon ──BPF── feth81 ⇄ feth80 ── macOS network stack
```

- `aic8800_fwload` pushes the AIC8800 firmware when that dongle appears in its mass-storage mode.
- `aic8800_wifi --daemon` runs the WPA2 4-way handshake and the data path for either chip. It bridges Ethernet frames to a `feth` pair.
  - AIC8800D80: the dongle firmware runs the MAC (LMAC); the daemon talks its USB message protocol.
  - RTL8852BU: the upstream Linux **rtw89** driver (`third_party/rtw89/`, unmodified) is compiled against
    `src/lkpi/`, a small userspace stand-in for the Linux kernel, USB and mac80211 APIs it uses, plus a
    station MLME (`src/lkpi/mlme.c`: scan, auth/assoc, keys, CCMP replay check, A-MPDU/BlockAck).
    The dongle first shows up as a Realtek "driver CD" (`0bda:1a2b`). Windows' WifiAutoInstallSrv sends it a
    SCSI eject on every plug; here the daemon detaches macOS's storage driver, and a per-user LaunchAgent
    (`com.aic8800mac.cdswitch`, started by launchd on plug-in) sends the same eject, because macOS gives
    access to removable-media interfaces only to the logged-in user. Wi-Fi mode follows in about 2 s.
- `aic_netsvc` creates the "USB Wi-Fi" network service.

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
