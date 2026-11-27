/* SPDX-License-Identifier: BSD-3-Clause */
#pragma once
#include "leds.h"
struct mc_subled { unsigned int color_index, brightness, intensity, channel; };
struct led_classdev_mc { struct led_classdev led_cdev; struct mc_subled *subled_info; unsigned int num_colors; };
