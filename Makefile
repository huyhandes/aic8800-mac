CC      ?= clang
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter
INC      = -Ithird_party/yokitea/common -Isrc
USB      = $(shell pkg-config --cflags --libs libusb-1.0 2>/dev/null || echo -I/opt/homebrew/opt/libusb/include/libusb-1.0 -L/opt/homebrew/opt/libusb/lib -lusb-1.0)
USB_DIR  = $(shell pkg-config --variable=prefix libusb-1.0 2>/dev/null || echo /opt/homebrew/opt/libusb)
FW       = -framework IOKit -framework CoreFoundation

all: build/usbwifid build/libusb-1.0.0.dylib build/usbwifi_netsvc build/USBWifi.app/Contents/MacOS/USBWifi

# "USB Wifi" menu bar app (installed as "/Applications/USB Wifi.app")
MENU_SRC = third_party/yokitea/apps/USBWifi
build/USBWifi.app/Contents/MacOS/USBWifi: $(MENU_SRC)/main.swift $(MENU_SRC)/Info.plist
	@mkdir -p $(@D)
	cp $(MENU_SRC)/Info.plist build/USBWifi.app/Contents/Info.plist
	swiftc -swift-version 5 -O -parse-as-library -framework Cocoa $< -o $@
	codesign --force --sign - build/USBWifi.app

build/usbwifi_netsvc: src/usbwifi_netsvc.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) $< -o $@ -framework SystemConfiguration $(FW)

# AIC8800D80 firmware loader, linked into usbwifid as its "fwload" subcommand
YK_HDR   = $(wildcard third_party/yokitea/common/*.h) # header-only: every includer rebuilds on a change
build/fwload.o: third_party/yokitea/fwload/main.c $(YK_HDR)
	@mkdir -p build
	$(CC) -c $(CFLAGS) $(INC) -Dmain=aic_fwload_main $< -o $@

# Realtek RTL8852BU: upstream Linux rtw89 (GPL-2.0 OR BSD-3-Clause, unmodified) on the src/lkpi mac80211 shim
RTW_OBJ  = $(patsubst third_party/rtw89/%.c,build/rtw/%.o,$(wildcard third_party/rtw89/*.c))
LK_OBJ   = $(patsubst %,build/lk/%.o,kernel usb mac80211 mlme cdcap) build/lk/rtw89_led.o
LK_HDR   = $(wildcard src/lkpi/include/*.h src/lkpi/include/*/*.h) src/lkpi/local.h src/lkpi/ccmp.h src/rtw89/rtwd.h src/wifi_drv.h src/rx_reord.h
build/rtw/%.o: third_party/rtw89/%.c $(LK_HDR)
	@mkdir -p $(@D)
	$(CC) -c -std=gnu11 -O2 -Isrc/lkpi/include -DCONFIG_RTW89_DEBUGMSG -Wno-everything $< -o $@
build/lk/rtw89_led.o: src/lkpi/rtw89_led.c $(LK_HDR)
	@mkdir -p $(@D)
	$(CC) -c -std=gnu11 -O2 -Isrc/lkpi/include -Ithird_party/rtw89 -Wno-everything $< -o $@
build/lk/%.o: src/lkpi/%.c $(LK_HDR)
	@mkdir -p $(@D)
	$(CC) -c -std=gnu11 $(CFLAGS) -Isrc/lkpi/include -I$(USB_DIR)/include/libusb-1.0 $< -o $@

# station core + one src/<chip>/drv_<chip>.c per chip family (wifi_drv.h)
CORE_SRC = src/usbwifid.c src/usbwifi_core.c src/aic8800/drv_aic8800.c src/rtw89/drv_rtw89.c
build/usbwifid: $(CORE_SRC) src/usbwifi_core.h src/wifi_drv.h src/wpa2.h src/rx_reord.h src/rtw89/rtwd.h src/wifi_ctl.h src/ft.h src/wpa3.h $(YK_HDR) build/fwload.o $(RTW_OBJ) $(LK_OBJ)
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) $(CORE_SRC) build/fwload.o $(RTW_OBJ) $(LK_OBJ) -o $@ $(USB) $(FW) -framework DiskArbitration
	install_name_tool -change $$(otool -L $@ | awk '/libusb/{print $$1}') @executable_path/libusb-1.0.0.dylib $@
	# ad-hoc's default requirement is the cdhash, so each build lost the cd-eject agent's Removable Volumes grant
	codesign --force --sign - -i com.usbwifi.usbwifid -r='designated => identifier "com.usbwifi.usbwifid"' $@

# bundled so the installed driver does not depend on Homebrew
build/libusb-1.0.0.dylib:
	@mkdir -p build
	cp $(USB_DIR)/lib/libusb-1.0.0.dylib $@ && chmod 755 $@
	install_name_tool -id @executable_path/libusb-1.0.0.dylib $@
	codesign --force --sign - $@

# double-click installer: required core + selectable drivers; the hidden setup pkg runs last
# (install.sh --setup), so it only wires up the drivers that were ticked. The optional clean pkg runs first
# (choices-outline order) and carries its own install.sh, since none may be installed yet
VERSION = 1.1.0
PKGROOT = build/pkgroot
HELPER  = Library/PrivilegedHelperTools/usbwifi
SUPDIR  = Library/Application Support/USB Wifi
pkg: all
	@test -d fw/aic8800D80 || { echo "missing fw/aic8800D80 (see INSTALL.md)"; exit 1; }
	@test -f fw/rtw89/rtw8852b_fw-2.bin || { echo "missing fw/rtw89/rtw8852b_fw-2.bin (see INSTALL.md)"; exit 1; }
	rm -rf build/pkgroot build/pkgscripts build/pkgs
	install -d "$(PKGROOT)/core/Applications" "$(PKGROOT)/core/$(HELPER)" "$(PKGROOT)/core/$(SUPDIR)/licenses" \
	  "$(PKGROOT)/aic/$(SUPDIR)/fw" "$(PKGROOT)/rtl/$(SUPDIR)/fw" "$(PKGROOT)/rtl/$(SUPDIR)/licenses" \
	  build/pkgscripts/core build/pkgscripts/setup build/pkgscripts/clean build/pkgs
	cp -R build/USBWifi.app "$(PKGROOT)/core/Applications/USB Wifi.app"
	install -m 755 build/usbwifid build/usbwifi_netsvc build/libusb-1.0.0.dylib scripts/install.sh "$(PKGROOT)/core/$(HELPER)/"
	install -m 644 LICENSE "$(PKGROOT)/core/$(SUPDIR)/licenses/LICENSE"
	install -m 644 third_party/yokitea/LICENSE "$(PKGROOT)/core/$(SUPDIR)/licenses/yokitea-LICENSE"
	install -m 644 third_party/rtw89/COPYING "$(PKGROOT)/core/$(SUPDIR)/licenses/rtw89-COPYING"
	install -m 644 $(USB_DIR)/COPYING "$(PKGROOT)/core/$(SUPDIR)/licenses/libusb-COPYING"
	cp -R fw/aic8800D80 "$(PKGROOT)/aic/$(SUPDIR)/fw/"
	install -d "$(PKGROOT)/rtl/$(SUPDIR)/fw/rtw89"
	install -m 644 fw/rtw89/rtw8852b_fw-2.bin "$(PKGROOT)/rtl/$(SUPDIR)/fw/rtw89/"
	install -m 644 fw/rtw89/LICENCE.rtlwifi_firmware.txt "$(PKGROOT)/rtl/$(SUPDIR)/licenses/"
	install -m 755 scripts/pkg-preinstall.sh build/pkgscripts/core/preinstall
	printf '#!/bin/bash\nexec "/$(HELPER)/install.sh" --setup\n' > build/pkgscripts/setup/postinstall
	chmod 755 build/pkgscripts/setup/postinstall
	install -m 755 scripts/install.sh build/pkgscripts/clean/
	printf '#!/bin/bash\nexec "$$(dirname "$$0")/install.sh" --clean\n' > build/pkgscripts/clean/preinstall
	chmod 755 build/pkgscripts/clean/preinstall
	pkgbuild --analyze --root "$(PKGROOT)/core" build/components.plist
	plutil -replace 0.BundleIsRelocatable -bool NO build/components.plist
	pkgbuild --root "$(PKGROOT)/core" --component-plist build/components.plist --scripts build/pkgscripts/core --identifier com.usbwifi.pkg --version $(VERSION) --ownership recommended --install-location / build/pkgs/core.pkg
	pkgbuild --root "$(PKGROOT)/aic" --identifier com.usbwifi.pkg.aic8800 --version $(VERSION) --ownership recommended --install-location / build/pkgs/aic8800.pkg
	pkgbuild --root "$(PKGROOT)/rtl" --identifier com.usbwifi.pkg.rtl8852bu --version $(VERSION) --ownership recommended --install-location / build/pkgs/rtl8852bu.pkg
	pkgbuild --nopayload --scripts build/pkgscripts/clean --identifier com.usbwifi.pkg.clean --version $(VERSION) build/pkgs/clean.pkg
	pkgbuild --nopayload --scripts build/pkgscripts/setup --identifier com.usbwifi.pkg.setup --version $(VERSION) build/pkgs/setup.pkg
	productbuild --distribution scripts/distribution.xml --package-path build/pkgs --version $(VERSION) build/USBWifi.pkg
.PHONY: pkg

clean:
	rm -rf build
.PHONY: all clean

# self-check (no root): WPA2 handshake and lkpi shim unit tests, then driver bring-up + scan against the plugged dongle
check: build/usbwifid build/libusb-1.0.0.dylib build/wpa2_test build/reord_test build/drv_contract_test build/kernel_test build/mac80211_test
	./build/wpa2_test
	./build/reord_test
	./build/drv_contract_test
	./build/kernel_test
	./build/mac80211_test
	AICD_NO_NET=1 ./build/usbwifid scan

build/wpa2_test: tests/wpa2_test.c src/wpa2.h src/wifi_ctl.h src/ft.h src/wpa3.h src/lkpi/ccmp.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) $< -o $@
build/reord_test: tests/reord_test.c src/rx_reord.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) $< -o $@
build/drv_contract_test: tests/drv_contract_test.c src/usbwifi_core.c src/usbwifi_core.h src/wifi_drv.h src/wifi_ctl.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) -DWIFI_RUN_DIR='"build/run"' $(filter %.c,$^) $(USB) -framework IOKit -o $@
build/kernel_test: src/lkpi/tests/kernel_test.c src/lkpi/kernel.c $(LK_HDR)
	$(CC) -std=gnu11 -Isrc/lkpi/include -Isrc/lkpi $(filter %.c,$^) -o $@
build/mac80211_test: src/lkpi/tests/mac80211_test.c src/lkpi/mac80211.c src/lkpi/kernel.c $(LK_HDR)
	$(CC) -std=gnu11 -Wno-everything -Isrc/lkpi/include -Isrc/lkpi $(filter %.c,$^) -o $@
.PHONY: check
