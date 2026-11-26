CC      ?= clang
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter
INC      = -Ithird_party/yokitea/common -Isrc
USB      = $(shell pkg-config --cflags --libs libusb-1.0)
FW       = -framework IOKit -framework CoreFoundation

all: build/aic8800_fwload build/aic8800_wifi

build/aic8800_fwload: third_party/yokitea/fwload/main.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) $< -o $@ $(FW) -framework DiskArbitration

build/aic8800_wifi: src/aic8800_wifi.c src/aicd_backend.c src/aicd_backend.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) src/aic8800_wifi.c src/aicd_backend.c -o $@ $(USB) $(FW)

clean:
	rm -rf build
.PHONY: all clean

# hardware self-check (no root): LMAC bring-up + scan against the plugged dongle
check: build/aic8800_wifi
	AICD_NO_NET=1 ./build/aic8800_wifi scan
.PHONY: check
