CC      ?= clang
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter
INC      = -Ithird_party/yokitea/common -Isrc
USB      = $(shell pkg-config --cflags --libs libusb-1.0)
USB_DYLIB = $(shell pkg-config --variable=libdir libusb-1.0)/libusb-1.0.0.dylib
FW       = -framework IOKit -framework CoreFoundation

all: build/aic8800_fwload build/aic8800_wifi build/libusb-1.0.0.dylib build/aic_netsvc build/AIC8800Menu.app/Contents/MacOS/AIC8800Menu

MENU_SRC = third_party/yokitea/apps/AIC8800Menu
build/AIC8800Menu.app/Contents/MacOS/AIC8800Menu: $(MENU_SRC)/main.swift $(MENU_SRC)/Info.plist
	@mkdir -p $(@D)
	cp $(MENU_SRC)/Info.plist build/AIC8800Menu.app/Contents/Info.plist
	swiftc -swift-version 5 -O -parse-as-library -framework Cocoa $< -o $@
	codesign --force --sign - build/AIC8800Menu.app

build/aic_netsvc: src/aic_netsvc.c src/aicd_backend.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) $< -o $@ -framework SystemConfiguration $(FW)

build/aic8800_fwload: third_party/yokitea/fwload/main.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) $< -o $@ $(FW) -framework DiskArbitration

build/aic8800_wifi: src/aic8800_wifi.c src/aicd_backend.c src/aicd_backend.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) src/aic8800_wifi.c src/aicd_backend.c -o $@ $(USB) $(FW)
	install_name_tool -change $$(otool -L $@ | awk '/libusb/{print $$1}') @executable_path/libusb-1.0.0.dylib $@
	codesign --force --sign - $@

# bundled so the installed driver does not depend on Homebrew
build/libusb-1.0.0.dylib:
	@mkdir -p build
	cp $(USB_DYLIB) $@ && chmod 755 $@
	install_name_tool -id @executable_path/libusb-1.0.0.dylib $@
	codesign --force --sign - $@

# double-click installer: payload + postinstall (= install.sh --setup)
PKGROOT = build/pkgroot
pkg: all
	rm -rf $(PKGROOT) build/pkgscripts
	install -d $(PKGROOT)/Applications $(PKGROOT)/Library/PrivilegedHelperTools/aic8800-mac "$(PKGROOT)/Library/Application Support/AIC8800/fw" build/pkgscripts
	cp -R build/AIC8800Menu.app $(PKGROOT)/Applications/
	install -m 755 build/aic8800_fwload build/aic8800_wifi build/aic_netsvc build/libusb-1.0.0.dylib scripts/install.sh $(PKGROOT)/Library/PrivilegedHelperTools/aic8800-mac/
	cp -R fw/aic8800D80 "$(PKGROOT)/Library/Application Support/AIC8800/fw/"
	printf '#!/bin/bash\nexec /Library/PrivilegedHelperTools/aic8800-mac/install.sh --setup\n' > build/pkgscripts/postinstall
	chmod 755 build/pkgscripts/postinstall
	pkgbuild --analyze --root $(PKGROOT) build/components.plist
	plutil -replace 0.BundleIsRelocatable -bool NO build/components.plist
	pkgbuild --root $(PKGROOT) --component-plist build/components.plist --scripts build/pkgscripts --identifier com.aic8800mac.pkg --version 1.0 --ownership recommended --install-location / build/AIC8800-mac.pkg
.PHONY: pkg

clean:
	rm -rf build
.PHONY: all clean

# hardware self-check (no root): LMAC bring-up + scan against the plugged dongle
check: build/aic8800_wifi
	AICD_NO_NET=1 ./build/aic8800_wifi scan
.PHONY: check
