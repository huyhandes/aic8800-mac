import Cocoa
import Darwin
import Security

/* one control socket per plugged dongle: <slot>.sock, created by its usbwifid worker */
private let kRunDir = "/var/run/usbwifi"
private let kLoginAgentLabel = "com.usbwifi.menu"

/* only the fields the menu reads: a required key the daemon stops sending would fail the whole decode */
struct WifiStatus: Decodable {
    let ok: Bool
    let present: Bool
    let bsd: String
    let mac: String
    let chip: String? /* absent from pre-1.1 daemons */
    let lmac_ready: Bool
    let associated: Bool
    let link_up: Bool
    let disc_reason: UInt32
    let ssid: String
    let freq: UInt32
    let connecting: Bool
    let auto_paused: Bool
    let saved_ssid: String
    let last_error: String
    let band_pref: String? /* "auto", "5" or "2.4"; absent from older daemons */
    let power_save: Bool? /* absent when the dongle's driver has no power save */
}

struct ScanBss: Decodable {
    let ssid: String
    let hidden: Bool
    let freq: UInt32
    let rssi: Int
    let sec: String
    let open: Bool
}

struct ScanResponse: Decodable {
    let ok: Bool
    let bss: [ScanBss]?
    let error: String?
}

struct BasicResponse: Decodable {
    let ok: Bool
    let error: String?
}

// Per-SSID passphrases in the user's login keychain (the daemon only keeps the one auto-join profile).
private func keychainQuery(_ ssid: String) -> [String: Any] {
    return [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.usbwifi.wifi",
            kSecAttrAccount as String: ssid]
}

private func keychainPassword(_ ssid: String) -> String? {
    var q = keychainQuery(ssid)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var out: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
    return String(data: d, encoding: .utf8)
}

private func keychainSave(_ ssid: String, _ pass: String) {
    /* update in place: delete-then-add loses the old password when the add fails */
    let data = Data(pass.utf8)
    var st = SecItemUpdate(keychainQuery(ssid) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
    if st == errSecItemNotFound {
        var q = keychainQuery(ssid)
        q[kSecValueData as String] = data
        q[kSecAttrLabel as String] = "USB Wi-Fi: \(ssid)"
        st = SecItemAdd(q as CFDictionary, nil)
    }
    if st != errSecSuccess { NSLog("USBWifi: keychain save for %@ failed: %d", ssid, st) }
}

private func keychainDelete(_ ssid: String) {
    SecItemDelete(keychainQuery(ssid) as CFDictionary)
}

private func hexEncode(_ s: String) -> String {
    return Data(s.utf8).map { String(format: "%02x", $0) }.joined()
}

/// (in, out) byte counters of an interface; if_data keeps them in 32 bits, so they wrap every 4 GB
private func interfaceBytes(_ bsdName: String) -> (UInt32, UInt32)? {
    var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else { return nil }
    defer { freeifaddrs(first) }
    var cur: UnsafeMutablePointer<ifaddrs>? = first
    while let node = cur {
        let i = node.pointee
        if i.ifa_addr?.pointee.sa_family == UInt8(AF_LINK), String(cString: i.ifa_name) == bsdName,
           let d = i.ifa_data?.assumingMemoryBound(to: if_data.self).pointee {
            return (d.ifi_ibytes, d.ifi_obytes)
        }
        cur = i.ifa_next
    }
    return nil
}

private let rateFormatter: ByteCountFormatter = {
    let f = ByteCountFormatter()
    f.countStyle = .file
    f.allowsNonnumericFormatting = false
    return f
}()
private func perSec(_ bytes: Double) -> String { rateFormatter.string(fromByteCount: Int64(bytes)) + "/s" }

private func ipv4AddressForInterface(_ bsdName: String) -> String? {
    guard !bsdName.isEmpty && bsdName != "unknown" else { return nil }
    var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else { return nil }
    defer { freeifaddrs(first) }

    var cur: UnsafeMutablePointer<ifaddrs>? = first
    while let node = cur {
        let iface = node.pointee
        if let namePtr = iface.ifa_name,
           let addrPtr = iface.ifa_addr,
           addrPtr.pointee.sa_family == UInt8(AF_INET) {
            let name = String(cString: namePtr)
            if name == bsdName {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let rc = getnameinfo(addrPtr,
                                     socklen_t(addrPtr.pointee.sa_len),
                                     &host,
                                     socklen_t(host.count),
                                     nil,
                                     0,
                                     NI_NUMERICHOST)
                if rc == 0 {
                    return String(cString: host)
                }
            }
        }
        cur = iface.ifa_next
    }
    return nil
}

private func sendDaemonCommand(_ sockPath: String, _ cmd: String, timeoutSec: Int = 5) -> Result<Data, Error> {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    if fd < 0 {
        return .failure(NSError(domain: NSPOSIXErrorDomain, code: Int(errno)))
    }
    defer { close(fd) }

    var tv = timeval(tv_sec: timeoutSec, tv_usec: 0)
    _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(sockPath.utf8CString)
    let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
    if pathBytes.count > maxLen {
        return .failure(NSError(domain: NSPOSIXErrorDomain, code: Int(ENAMETOOLONG)))
    }
    withUnsafeMutableBytes(of: &addr.sun_path) { raw in
        for i in 0..<pathBytes.count {
            raw[i] = UInt8(bitPattern: pathBytes[i])
        }
    }

    let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
    let rc = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            Darwin.connect(fd, sa, addrLen)
        }
    }
    if rc != 0 {
        return .failure(NSError(domain: NSPOSIXErrorDomain, code: Int(errno)))
    }

    let payload = Array((cmd + "\n").utf8)
    var sent = 0
    while sent < payload.count {
        let n = payload.withUnsafeBytes { buf in
            Darwin.write(fd, buf.baseAddress!.advanced(by: sent), payload.count - sent)
        }
        if n <= 0 {
            return .failure(NSError(domain: NSPOSIXErrorDomain, code: Int(errno)))
        }
        sent += n
    }

    var reply = Data()
    var chunk = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = Darwin.read(fd, &chunk, chunk.count)
        if n < 0 {
            if errno == EINTR { continue }
            return .failure(NSError(domain: NSPOSIXErrorDomain, code: Int(errno)))
        }
        if n == 0 {
            break
        }
        reply.append(contentsOf: chunk[0..<n])
        if chunk[0..<n].contains(0x0a) {
            break
        }
    }
    /* SSIDs are raw bytes: replace invalid UTF-8 so one odd neighbour SSID cannot fail the JSON decode */
    return .success(Data(String(decoding: reply, as: UTF8.self).utf8))
}

/// One plugged dongle, driven by its own usbwifid worker. Touched on the main thread only.
final class Adapter {
    let slot: Int
    let sock: String
    var status: WifiStatus?
    var ipv4: String?
    var isScanning = false
    var networks: [ScanBss] = []
    var message: String?
    var pendingAutoScan = false
    var wasReady = false
    var popAfterScan = false
    var scannedAt = Date.distantPast
    var rate: (down: Double, up: Double)? /* bytes/s on the network interface */
    var lastBytes: (UInt32, UInt32)?
    var lastAt = Date.distantPast

    init(slot: Int) {
        self.slot = slot
        self.sock = "\(kRunDir)/\(slot).sock"
    }

    /// same name as its network service in System Settings > Network
    var name: String { slot == 0 ? "USB Wi-Fi" : "USB Wi-Fi \(slot + 1)" }
    var ready: Bool { status.map { $0.present && $0.lmac_ready } ?? false }
}

/// (adapter, network) for a network menu item
private final class BandChoice {
    let adapter: Adapter
    let band: String
    init(_ adapter: Adapter, _ band: String) { self.adapter = adapter; self.band = band }
}

private final class NetChoice {
    let adapter: Adapter
    let bss: ScanBss
    init(_ adapter: Adapter, _ bss: ScanBss) { self.adapter = adapter; self.bss = bss }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private let menu = NSMenu()
    private let ioQueue = DispatchQueue(label: "com.usbwifi.app.io", qos: .userInitiated, attributes: .concurrent)

    private var pollTimer: Timer?
    private var daemonOffline = true
    private var adapters: [Int: Adapter] = [:] /* by slot */

    private var sortedAdapters: [Adapter] { adapters.values.sorted { $0.slot < $1.slot } }

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        menu.delegate = self
        menu.autoenablesItems = false
        statusItem.menu = menu

        updateIconAndTitle()
        rebuildMenu()

        pollStatus()
        let t = Timer(timeInterval: 2.0, repeats: true) { [weak self] _ in self?.pollStatus() }
        RunLoop.main.add(t, forMode: .common) /* .common: keeps polling while the menu is open */
        pollTimer = t
    }

    func applicationWillTerminate(_ notification: Notification) {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    func menuWillOpen(_ menu: NSMenu) {
        guard menu === self.menu else { return }
        pollStatus()
        // a scan while associated takes the radio off-channel for ~5 s (traffic stalls), so a connected
        // adapter keeps a list under a minute old; "Scan Networks" in its section still forces one
        for a in sortedAdapters where a.ready && !a.isScanning {
            if a.status?.associated == true && Date().timeIntervalSince(a.scannedAt) < 60 { continue }
            triggerScan(a)
        }
        rebuildMenu()
    }

    /// slots that have a worker socket right now
    private func liveSlots() -> [Int]? {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: kRunDir) else { return nil }
        return names.compactMap { n in n.hasSuffix(".sock") ? Int(n.dropLast(5)) : nil }
    }

    private func pollStatus() {
        guard let slots = liveSlots() else {
            daemonOffline = true
            adapters.removeAll()
            updateIconAndTitle()
            rebuildMenu()
            return
        }
        daemonOffline = false
        for s in Set(adapters.keys).subtracting(slots) { adapters.removeValue(forKey: s) }
        for s in slots where adapters[s] == nil { adapters[s] = Adapter(slot: s) }
        updateIconAndTitle()
        rebuildMenu()
        for a in sortedAdapters { pollStatus(a) }
    }

    private func pollStatus(_ a: Adapter) {
        ioQueue.async { [weak self] in
            var st: WifiStatus?
            if case .success(let data) = sendDaemonCommand(a.sock, "STATUS", timeoutSec: 3),
               let s = try? JSONDecoder().decode(WifiStatus.self, from: data), s.ok {
                st = s
            }
            let ip = st.flatMap { ($0.associated && $0.link_up) ? ipv4AddressForInterface($0.bsd) : nil }
            let bytes = st.flatMap { ($0.associated && $0.link_up) ? interfaceBytes($0.bsd) : nil }
            DispatchQueue.main.async {
                guard let self = self, self.adapters[a.slot] === a else { return }
                a.status = st
                a.ipv4 = ip
                // speed over the last >= 1 s: action replies poll again sooner, which would give noisy rates
                let now = Date(), dt = now.timeIntervalSince(a.lastAt)
                if bytes == nil {
                    a.lastBytes = nil
                    a.rate = nil
                } else if a.lastBytes == nil || dt >= 1 {
                    if let p = a.lastBytes, let b = bytes {
                        a.rate = (Double(b.0 &- p.0) / dt, Double(b.1 &- p.1) / dt)
                    }
                    a.lastBytes = bytes
                    a.lastAt = now
                }
                if let st = st {
                    // dongle just came up with no saved network -> open the picker once its scan is in
                    if a.ready && !a.wasReady && st.saved_ssid.isEmpty && !st.associated && !st.connecting {
                        a.popAfterScan = true
                        a.networks = []
                        a.pendingAutoScan = false
                    }
                    // not while the daemon connects or just linked: the scan would delay its retry and DHCP;
                    // opening the menu still scans
                    if !a.pendingAutoScan && a.ready && a.networks.isEmpty && !st.connecting && !st.associated {
                        a.pendingAutoScan = true
                        self.triggerScan(a)
                    }
                }
                a.wasReady = a.ready
                self.updateIconAndTitle()
                self.rebuildMenu()
            }
        }
    }

    private func triggerScan(_ a: Adapter) {
        guard !a.isScanning else { return }
        a.isScanning = true
        rebuildMenu()

        ioQueue.async { [weak self] in
            let res = sendDaemonCommand(a.sock, "SCAN", timeoutSec: 15)
            DispatchQueue.main.async {
                guard let self = self else { return }
                a.isScanning = false
                switch res {
                case .success(let data):
                    if let resp = try? JSONDecoder().decode(ScanResponse.self, from: data),
                       resp.ok, let list = resp.bss {
                        a.networks = self.deduplicateAndSort(list, active: a.status)
                        a.scannedAt = Date()
                        a.message = nil
                        if a.popAfterScan {
                            a.popAfterScan = false
                            self.rebuildMenu()
                            NSApp.activate(ignoringOtherApps: true)
                            self.statusItem.button?.performClick(nil)
                        }
                    } else if let resp = try? JSONDecoder().decode(ScanResponse.self, from: data),
                              let err = resp.error {
                        a.message = err
                    }
                case .failure(let err):
                    a.message = err.localizedDescription
                }
                self.rebuildMenu()
            }
        }
    }

    private func deduplicateAndSort(_ raw: [ScanBss], active st: WifiStatus?) -> [ScanBss] {
        var bestBySsid: [String: ScanBss] = [:]
        for item in raw where !item.hidden && !item.ssid.isEmpty {
            if let existing = bestBySsid[item.ssid] {
                if item.rssi > existing.rssi {
                    bestBySsid[item.ssid] = item
                }
            } else {
                bestBySsid[item.ssid] = item
            }
        }
        let activeSsid = (st?.associated == true) ? st?.ssid : nil
        return bestBySsid.values.sorted { a, b in
            if a.ssid == activeSsid && b.ssid != activeSsid { return true }
            if b.ssid == activeSsid && a.ssid != activeSsid { return false }
            return a.rssi > b.rssi
        }
    }

    private func sendSimpleAction(_ a: Adapter, _ cmd: String, timeoutSec: Int = 10) {
        ioQueue.async { [weak self] in
            let res = sendDaemonCommand(a.sock, cmd, timeoutSec: timeoutSec)
            DispatchQueue.main.async {
                switch res {
                case .success(let data):
                    if let resp = try? JSONDecoder().decode(BasicResponse.self, from: data) {
                        a.message = resp.ok ? nil : (resp.error ?? "Command failed")
                    } else {
                        a.message = "No reply from usbwifid"
                    }
                case .failure(let err):
                    a.message = err.localizedDescription
                }
                self?.pollStatus(a)
            }
        }
    }

    /// keychainSec != nil: passphrase came from the keychain; if it is rejected, drop it and ask again.
    private func performConnect(_ a: Adapter, ssid: String, passphrase: String?, save: Bool, keychainSec: String? = nil) {
        let ssidHex = hexEncode(ssid)
        let passHex = (passphrase != nil && !passphrase!.isEmpty) ? hexEncode(passphrase!) : "-"
        let saveFlag = save ? 1 : 0
        a.message = nil
        updateIconAndTitle()
        rebuildMenu()

        ioQueue.async { [weak self] in
            /* longer than the daemon's own 25 s limit, so its timeout reply arrives instead of a socket error */
            let res = sendDaemonCommand(a.sock, "CONNECT_HEX \(ssidHex) \(passHex) \(saveFlag)", timeoutSec: 40)
            DispatchQueue.main.async {
                switch res {
                case .success(let data):
                    guard let resp = try? JSONDecoder().decode(BasicResponse.self, from: data) else {
                        a.message = "No reply from usbwifid" /* never save a password the daemon did not confirm */
                        break
                    }
                    if !resp.ok {
                        let err = resp.error ?? "Connection failed"
                        a.message = err
                        if err == "Wrong password", let sec = keychainSec {
                            keychainDelete(ssid)
                            a.message = "Wrong saved password for \"\(ssid)\""
                            self?.promptForPassword(a, ssid: ssid, secLabel: sec, allowEditSsid: false)
                        }
                    } else {
                        a.message = nil
                        if save, let p = passphrase, !p.isEmpty { keychainSave(ssid, p) }
                    }
                case .failure(let err):
                    a.message = err.localizedDescription
                }
                self?.pollStatus(a)
            }
        }
    }

    /// one icon for all adapters: connecting beats connected beats present-but-down
    private func updateIconAndTitle() {
        guard let button = statusItem.button else { return }
        let sts = sortedAdapters.compactMap { $0.status }.filter { $0.present }
        let symbolName: String
        var title = ""

        if daemonOffline || sts.isEmpty {
            symbolName = "wifi.slash"
        } else if sts.contains(where: { $0.connecting }) {
            symbolName = "wifi"
            title = " …"
        } else if sts.contains(where: { $0.associated && $0.link_up }) {
            symbolName = "wifi"
        } else {
            symbolName = "wifi.exclamationmark"
        }

        if let img = NSImage(systemSymbolName: symbolName, accessibilityDescription: "USB Wi-Fi") {
            img.isTemplate = true
            button.image = img
        } else {
            button.image = nil
            title = "WiFi"
        }
        button.title = title
    }

    private func disabledInfoItem(_ text: String, bold: Bool = false) -> NSMenuItem {
        let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        item.isEnabled = false
        if bold {
            let font = NSFont.menuFont(ofSize: 13)
            let boldFont = NSFontManager.shared.convert(font, toHaveTrait: .boldFontMask)
            item.attributedTitle = NSAttributedString(string: text, attributes: [.font: boldFont])
        }
        return item
    }

    private func actionItem(_ title: String, _ sel: Selector, _ obj: Any?, key: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: sel, keyEquivalent: key)
        item.target = self
        item.representedObject = obj
        return item
    }

    /// copies `src` onto `dst` item by item while the layout matches, so an open menu keeps its
    /// highlighted row and open submenu across refreshes
    private func sync(_ dst: NSMenu, _ src: NSMenu) {
        let same = dst.items.count == src.items.count && zip(dst.items, src.items).allSatisfy {
            $0.isSeparatorItem == $1.isSeparatorItem && ($0.submenu == nil) == ($1.submenu == nil)
        }
        guard same else {
            let items = src.items
            src.removeAllItems()
            dst.removeAllItems()
            items.forEach { dst.addItem($0) }
            return
        }
        for (d, s) in zip(dst.items, src.items) where !s.isSeparatorItem {
            d.title = s.title
            d.attributedTitle = s.attributedTitle
            d.action = s.action
            d.target = s.target
            d.representedObject = s.representedObject
            d.keyEquivalent = s.keyEquivalent
            d.isEnabled = s.isEnabled
            d.state = s.state
            d.image = s.image
            if let ds = d.submenu, let ss = s.submenu { sync(ds, ss) }
        }
    }

    private func rebuildMenu() {
        let menu = NSMenu()
        defer { sync(self.menu, menu) }
        let list = sortedAdapters.filter { $0.status?.present == true }

        if daemonOffline {
            menu.addItem(disabledInfoItem("USB Wi-Fi Driver Offline", bold: true))
            menu.addItem(disabledInfoItem("Driver daemon not running: reinstall USB Wifi"))
        } else if list.isEmpty {
            menu.addItem(disabledInfoItem("USB Wi-Fi Adapter Not Found", bold: true))
            menu.addItem(disabledInfoItem("Plug in a supported adapter (AIC8800D80, RTL8852BU)"))
        } else {
            // one adapter: the network list sits in the menu itself; several: one section each, with
            // the networks in a submenu so every adapter's status stays in view
            for (i, a) in list.enumerated() {
                if i > 0 { menu.addItem(NSMenuItem.separator()) }
                addAdapterSection(a, multi: list.count > 1, menu)
            }
        }

        menu.addItem(NSMenuItem.separator())

        let loginItem = actionItem("Launch at Login", #selector(onToggleLogin), nil)
        loginItem.state = isLoginAgentEnabled() ? .on : .off
        menu.addItem(loginItem)
        menu.addItem(actionItem("Open Wi-Fi Log", #selector(onOpenLog), nil))
        menu.addItem(actionItem("Quit USB Wifi", #selector(onQuit), nil, key: "q"))
    }

    private func addAdapterSection(_ a: Adapter, multi: Bool, _ menu: NSMenu) {
        guard let st = a.status else { return }
        let chip = (st.chip?.isEmpty == false) ? st.chip! : "Adapter"
        if multi {
            menu.addItem(disabledInfoItem("\(a.name) — \(chip)", bold: true))
        }
        let ind = multi ? "  " : ""

        if !st.lmac_ready {
            menu.addItem(disabledInfoItem("\(ind)Initializing Adapter… (\(st.bsd))", bold: !multi))
        } else if st.connecting {
            menu.addItem(disabledInfoItem("\(ind)Connecting… (\(st.bsd))", bold: !multi))
        } else if st.associated && st.link_up {
            let band = st.freq >= 5000 ? "5 GHz" : "2.4 GHz"
            let ssidShow = st.ssid.isEmpty ? "(hidden)" : st.ssid
            menu.addItem(disabledInfoItem("\(ind)Connected: \(ssidShow)", bold: !multi))
            let ipText = a.ipv4 ?? "DHCP pending…"
            menu.addItem(disabledInfoItem("\(ind)  \(band) | \(st.bsd) | IP \(ipText)"))
            let speed = a.rate.map { "↓ \(perSec($0.down))   ↑ \(perSec($0.up))" } ?? "↓ …   ↑ …"
            menu.addItem(disabledInfoItem("\(ind)  \(speed)"))
        } else {
            let extra = st.auto_paused ? " (paused)" : ""
            menu.addItem(disabledInfoItem("\(ind)Disconnected\(extra) | \(st.bsd)", bold: !multi))
            if st.disc_reason != 0 {
                menu.addItem(disabledInfoItem("\(ind)  Last disconnect reason: \(st.disc_reason)"))
            }
        }
        menu.addItem(disabledInfoItem(multi ? "\(ind)  \(st.mac)" : "  Adapter: \(chip) | \(st.mac)"))

        let err = a.message ?? (st.last_error.isEmpty ? nil : st.last_error)
        if let e = err, !e.isEmpty {
            menu.addItem(disabledInfoItem("\(ind)⚠ \(e)"))
        }
        guard st.lmac_ready else { return }

        if !multi { menu.addItem(NSMenuItem.separator()) }
        if st.associated || st.connecting {
            menu.addItem(actionItem("\(ind)Disconnect", #selector(onDisconnect(_:)), a))
        }
        if !st.saved_ssid.isEmpty {
            menu.addItem(actionItem("\(ind)Forget \"\(st.saved_ssid)\"", #selector(onForget(_:)), a))
        }
        if let pref = st.band_pref { /* each dongle keeps its own, applied at its next connect */
            let bands = NSMenu()
            bands.autoenablesItems = false
            for (title, v) in [("Auto", "auto"), ("5 GHz", "5"), ("2.4 GHz", "2.4")] {
                let it = actionItem(title, #selector(onBand(_:)), BandChoice(a, v))
                it.state = pref == v ? .on : .off
                bands.addItem(it)
            }
            let sub = NSMenuItem(title: "\(ind)Preferred Band", action: nil, keyEquivalent: "")
            sub.submenu = bands
            menu.addItem(sub)
        }
        if let ps = st.power_save { /* off by default: less heat and power, but higher latency */
            let it = actionItem("\(ind)Power Saving", #selector(onPowerSave(_:)), a)
            it.state = ps ? .on : .off
            menu.addItem(it)
        }

        let nets: NSMenu
        if multi {
            nets = NSMenu()
            nets.autoenablesItems = false
            let sub = NSMenuItem(title: "\(ind)Choose Network", action: nil, keyEquivalent: "")
            sub.submenu = nets
            menu.addItem(sub)
        } else {
            nets = menu
            menu.addItem(NSMenuItem.separator())
        }

        let scanItem = actionItem(a.isScanning ? "Scanning Networks…" : "Scan Networks", #selector(onScan(_:)), a,
                                  key: multi ? "" : "r")
        scanItem.isEnabled = !a.isScanning
        nets.addItem(scanItem)

        if a.networks.isEmpty && !a.isScanning {
            nets.addItem(disabledInfoItem("  No networks scanned yet"))
        } else {
            for bss in a.networks {
                let netItem = actionItem(bss.ssid, #selector(onSelectNetwork(_:)), NetChoice(a, bss))
                netItem.state = (st.associated && st.ssid == bss.ssid) ? .on : .off
                let sym = bss.open ? "wifi" : "lock.fill"
                if let icon = NSImage(systemSymbolName: sym, accessibilityDescription: bss.sec) {
                    icon.isTemplate = true
                    netItem.image = icon
                }
                nets.addItem(netItem)
            }
        }
        nets.addItem(actionItem("Join Other / Hidden Network…", #selector(onJoinHidden(_:)), a))
    }

    @objc private func onScan(_ sender: NSMenuItem) {
        if let a = sender.representedObject as? Adapter { triggerScan(a) }
    }

    @objc private func onDisconnect(_ sender: NSMenuItem) {
        if let a = sender.representedObject as? Adapter { sendSimpleAction(a, "DISCONNECT", timeoutSec: 8) }
    }

    @objc private func onForget(_ sender: NSMenuItem) {
        guard let a = sender.representedObject as? Adapter else { return }
        // the keychain password is shared by every adapter; keep it while another one still uses the network
        if let s = a.status?.saved_ssid, !s.isEmpty,
           !sortedAdapters.contains(where: { $0 !== a && $0.status?.saved_ssid == s }) {
            keychainDelete(s)
        }
        sendSimpleAction(a, "FORGET", timeoutSec: 8)
    }

    @objc private func onSelectNetwork(_ sender: NSMenuItem) {
        guard let c = sender.representedObject as? NetChoice else { return }
        let bss = c.bss
        if bss.open {
            performConnect(c.adapter, ssid: bss.ssid, passphrase: nil, save: true)
            return
        }
        if let pw = keychainPassword(bss.ssid) {
            performConnect(c.adapter, ssid: bss.ssid, passphrase: pw, save: true, keychainSec: bss.sec)
            return
        }
        promptForPassword(c.adapter, ssid: bss.ssid, secLabel: bss.sec, allowEditSsid: false)
    }

    @objc private func onJoinHidden(_ sender: NSMenuItem) {
        guard let a = sender.representedObject as? Adapter else { return }
        promptForPassword(a, ssid: "", secLabel: "WPA2-PSK or Open", allowEditSsid: true)
    }

    private func promptForPassword(_ a: Adapter, ssid: String, secLabel: String, allowEditSsid: Bool) {
        NSApp.activate(ignoringOtherApps: true)

        let alert = NSAlert()
        alert.alertStyle = .informational
        let via = adapters.count > 1 ? " with \(a.name)" : ""
        alert.messageText = allowEditSsid
            ? "Join Wi-Fi Network\(via)"
            : "Connect to \"\(ssid)\"\(via)"
        alert.informativeText = allowEditSsid
            ? "Enter the network SSID and optional WPA2 passphrase (leave password blank for Open):"
            : "Security: \(secLabel)"
        alert.addButton(withTitle: "Join")
        alert.addButton(withTitle: "Cancel")

        let stackHeight: CGFloat = allowEditSsid ? 92 : 60
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 290, height: stackHeight))

        var y: CGFloat = stackHeight - 24
        var ssidField: NSTextField?
        if allowEditSsid {
            let f = NSTextField(frame: NSRect(x: 0, y: y, width: 290, height: 24))
            f.placeholderString = "Network SSID"
            f.stringValue = ssid
            container.addSubview(f)
            ssidField = f
            y -= 32
        }

        let secField = NSSecureTextField(frame: NSRect(x: 0, y: y, width: 290, height: 24))
        secField.placeholderString = allowEditSsid ? "Passphrase (8..63 chars, blank if open)" : "Password"
        container.addSubview(secField)
        y -= 28

        let rememberCheck = NSButton(checkboxWithTitle: "Remember this network", target: nil, action: nil)
        rememberCheck.frame = NSRect(x: 0, y: y, width: 290, height: 20)
        rememberCheck.state = .on
        container.addSubview(rememberCheck)

        alert.accessoryView = container
        alert.window.initialFirstResponder = ssidField ?? secField

        let response = alert.runModal()
        guard response == .alertFirstButtonReturn else { return }

        let chosenSsid = (ssidField?.stringValue ?? ssid).trimmingCharacters(in: .whitespacesAndNewlines)
        let pass = secField.stringValue
        guard !chosenSsid.isEmpty else { return }

        if !allowEditSsid && pass.count < 8 {
            a.message = "Passphrase must be at least 8 characters"
            rebuildMenu()
            return
        }
        if !pass.isEmpty && (pass.count < 8 || pass.count > 63) {
            a.message = "Passphrase must be 8..63 characters"
            rebuildMenu()
            return
        }

        performConnect(a,
                       ssid: chosenSsid,
                       passphrase: pass.isEmpty ? nil : pass,
                       save: rememberCheck.state == .on)
    }

    private func loginAgentURL() -> URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent("Library/LaunchAgents/\(kLoginAgentLabel).plist")
    }

    private func isLoginAgentEnabled() -> Bool {
        return FileManager.default.fileExists(atPath: loginAgentURL().path)
    }

    @objc private func onToggleLogin() {
        let url = loginAgentURL()
        let fm = FileManager.default
        if fm.fileExists(atPath: url.path) {
            try? fm.removeItem(at: url)
            rebuildMenu()
            return
        }

        let exePath = Bundle.main.executablePath ?? "/Applications/USB Wifi.app/Contents/MacOS/USBWifi"
        let plist: [String: Any] = [
            "Label": kLoginAgentLabel,
            "ProgramArguments": [exePath],
            "RunAtLoad": true,
            "KeepAlive": false
        ]
        try? fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) {
            try? data.write(to: url)
        }
        rebuildMenu()
    }

    @objc private func onBand(_ sender: NSMenuItem) {
        guard let c = sender.representedObject as? BandChoice else { return }
        sendSimpleAction(c.adapter, "BAND \(c.band)")
    }

    @objc private func onPowerSave(_ sender: NSMenuItem) {
        guard let a = sender.representedObject as? Adapter else { return }
        sendSimpleAction(a, sender.state == .on ? "POWERSAVE off" : "POWERSAVE on")
    }

    @objc private func onOpenLog() {
        let url = URL(fileURLWithPath: "/var/log/com.usbwifi.wifi.log")
        NSWorkspace.shared.open(url)
    }

    @objc private func onQuit() {
        NSApplication.shared.terminate(nil)
    }
}

@main
enum USBWifiMain {
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}
