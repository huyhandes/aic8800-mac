/* SPDX-License-Identifier: BSD-3-Clause */
#pragma once
#include "../lkpi.h"
/* shortcut: LED class is compiled out (no CONFIG_LEDS), rtw89 only embeds these; add fields if LED support is wanted */
enum led_brightness { LED_OFF = 0, LED_ON = 1, LED_FULL = 255 };
struct led_classdev { const char *name; enum led_brightness max_brightness; };
