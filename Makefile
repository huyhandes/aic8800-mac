CC      ?= clang
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter
INC      = -Ithird_party/yokitea/common -Isrc
USB      = $(shell pkg-config --cflags --libs libusb-1.0 2>/dev/null || echo -I/opt/homebrew/opt/libusb/include/libusb-1.0 -L/opt/homebrew/opt/libusb/lib -lusb-1.0)
USB_DIR  = $(shell pkg-config --variable=prefix libusb-1.0 2>/dev/null || echo /opt/homebrew/opt/libusb)
FW       = -framework IOKit -framework CoreFoundation

all: build/aic8800_fwload build/aic8800_wifi build/libusb-1.0.0.dylib build/aic_netsvc build/USBWifi.app/Contents/MacOS/USBWifi

# "USB Wifi" menu bar app (installed as "/Applications/USB Wifi.app")
MENU_SRC = third_party/yokitea/apps/AIC8800Menu
build/USBWifi.app/Contents/MacOS/USBWifi: $(MENU_SRC)/main.swift $(MENU_SRC)/Info.plist
	@mkdir -p $(@D)
	cp $(MENU_SRC)/Info.plist build/USBWifi.app/Contents/Info.plist
	swiftc -swift-version 5 -O -parse-as-library -framework Cocoa $< -o $@
	codesign --force --sign - build/USBWifi.app

build/aic_netsvc: src/aic_netsvc.c src/aicd_backend.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) $< -o $@ -framework SystemConfiguration $(FW)

build/aic8800_fwload: third_party/yokitea/fwload/main.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) $< -o $@ $(FW) -framework DiskArbitration

# Realtek RTL8852BU: upstream Linux rtw89 (GPL-2.0 OR BSD-3-Clause, unmodified) on the src/lkpi mac80211 shim
RTW_OBJ  = $(patsubst third_party/rtw89/%.c,build/rtw/%.o,$(wildcard third_party/rtw89/*.c))
LK_OBJ   = $(patsubst %,build/lk/%.o,kernel usb mac80211 mlme cdcap)
LK_HDR   = $(wildcard src/lkpi/include/*.h src/lkpi/include/*/*.h) src/lkpi/local.h src/rtwd.h
build/rtw/%.o: third_party/rtw89/%.c $(LK_HDR)
	@mkdir -p $(@D)
	$(CC) -c -std=gnu11 -O2 -Isrc/lkpi/include -DCONFIG_RTW89_DEBUGMSG -Wno-everything $< -o $@
build/lk/%.o: src/lkpi/%.c $(LK_HDR)
	@mkdir -p $(@D)
	$(CC) -c -std=gnu11 $(CFLAGS) -Isrc/lkpi/include -Ithird_party/yokitea/common -I$(USB_DIR)/include/libusb-1.0 $< -o $@

build/aic8800_wifi: src/aic8800_wifi.c src/aicd_backend.c src/aicd_backend.h $(RTW_OBJ) $(LK_OBJ)
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) src/aic8800_wifi.c src/aicd_backend.c $(RTW_OBJ) $(LK_OBJ) -o $@ $(USB) $(FW)
	install_name_tool -change $$(otool -L $@ | awk '/libusb/{print $$1}') @executable_path/libusb-1.0.0.dylib $@
	codesign --force --sign - $@

# bundled so the installed driver does not depend on Homebrew
build/libusb-1.0.0.dylib:
	@mkdir -p build
	cp $(USB_DIR)/lib/libusb-1.0.0.dylib $@ && chmod 755 $@
	install_name_tool -id @executable_path/libusb-1.0.0.dylib $@
	codesign --force --sign - $@

# double-click installer: required core + selectable drivers; the hidden setup pkg runs last
# (install.sh --setup), so it only wires up the drivers that were ticked
VERSION = 1.1.0
PKGROOT = build/pkgroot
HELPER  = Library/PrivilegedHelperTools/aic8800-mac
SUPDIR  = Library/Application Support/AIC8800
pkg: all
	@test -d fw/aic8800D80 || { echo "missing fw/aic8800D80 (see INSTALL.md)"; exit 1; }
	@test -f fw/rtw89/rtw8852b_fw-2.bin || { echo "missing fw/rtw89/rtw8852b_fw-2.bin (see INSTALL.md)"; exit 1; }
	rm -rf build/pkgroot build/pkgscripts build/pkgs
	install -d "$(PKGROOT)/core/Applications" "$(PKGROOT)/core/$(HELPER)" "$(PKGROOT)/core/$(SUPDIR)/licenses" \
	  "$(PKGROOT)/aic/$(HELPER)" "$(PKGROOT)/aic/$(SUPDIR)/fw" "$(PKGROOT)/rtl/$(SUPDIR)/fw" "$(PKGROOT)/rtl/$(SUPDIR)/licenses" \
	  build/pkgscripts/core build/pkgscripts/setup build/pkgs
	cp -R build/USBWifi.app "$(PKGROOT)/core/Applications/USB Wifi.app"
	install -m 755 build/aic8800_wifi build/aic_netsvc build/libusb-1.0.0.dylib scripts/install.sh "$(PKGROOT)/core/$(HELPER)/"
	install -m 644 LICENSE "$(PKGROOT)/core/$(SUPDIR)/licenses/LICENSE"
	install -m 644 third_party/yokitea/LICENSE "$(PKGROOT)/core/$(SUPDIR)/licenses/yokitea-LICENSE"
	install -m 644 third_party/rtw89/COPYING "$(PKGROOT)/core/$(SUPDIR)/licenses/rtw89-COPYING"
	install -m 644 $(USB_DIR)/COPYING "$(PKGROOT)/core/$(SUPDIR)/licenses/libusb-COPYING"
	install -m 755 build/aic8800_fwload "$(PKGROOT)/aic/$(HELPER)/"
	cp -R fw/aic8800D80 "$(PKGROOT)/aic/$(SUPDIR)/fw/"
	install -d "$(PKGROOT)/rtl/$(SUPDIR)/fw/rtw89"
	install -m 644 fw/rtw89/rtw8852b_fw-2.bin "$(PKGROOT)/rtl/$(SUPDIR)/fw/rtw89/"
	install -m 644 fw/rtw89/LICENCE.rtlwifi_firmware.txt "$(PKGROOT)/rtl/$(SUPDIR)/licenses/"
	install -m 755 scripts/pkg-preinstall.sh build/pkgscripts/core/preinstall
	printf '#!/bin/bash\nexec "/$(HELPER)/install.sh" --setup\n' > build/pkgscripts/setup/postinstall
	chmod 755 build/pkgscripts/setup/postinstall
	pkgbuild --analyze --root "$(PKGROOT)/core" build/components.plist
	plutil -replace 0.BundleIsRelocatable -bool NO build/components.plist
	pkgbuild --root "$(PKGROOT)/core" --component-plist build/components.plist --scripts build/pkgscripts/core --identifier com.aic8800mac.pkg --version $(VERSION) --ownership recommended --install-location / build/pkgs/core.pkg
	pkgbuild --root "$(PKGROOT)/aic" --identifier com.aic8800mac.pkg.aic8800 --version $(VERSION) --ownership recommended --install-location / build/pkgs/aic8800.pkg
	pkgbuild --root "$(PKGROOT)/rtl" --identifier com.aic8800mac.pkg.rtl8852bu --version $(VERSION) --ownership recommended --install-location / build/pkgs/rtl8852bu.pkg
	pkgbuild --nopayload --scripts build/pkgscripts/setup --identifier com.aic8800mac.pkg.setup --version $(VERSION) build/pkgs/setup.pkg
	productbuild --distribution scripts/distribution.xml --package-path build/pkgs --version $(VERSION) build/USBWifi.pkg
.PHONY: pkg

clean:
	rm -rf build
.PHONY: all clean

# self-check (no root): WPA2 handshake unit test, then driver bring-up + scan against the plugged dongle
check: build/aic8800_wifi build/libusb-1.0.0.dylib build/wpa2_test
	./build/wpa2_test
	AICD_NO_NET=1 ./build/aic8800_wifi scan

build/wpa2_test: tests/wpa2_test.c third_party/yokitea/common/aic8800_wpa2.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) $< -o $@
.PHONY: check
