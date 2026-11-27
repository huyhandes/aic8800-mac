// SPDX-License-Identifier: BSD-3-Clause
/* The RTL8852BU's LED, which rtw89 leaves alone (8852B has no led_desc). Realtek's own driver
   (phl/hal_g6/mac/mac_ax: gpio.c, mac_8852b/gpio_8852b.c) muxes WL_LED onto GPIO8; here it is
   switched by software (LED_CFG mode 0, value bit) so it can show
   the connection state. Needs the MAC powered: call after the radio starts. */
#include "core.h"
#include "reg.h"

#define R_AX_LED_CFG 0x004C

void rtwd_led_init(struct ieee80211_hw *hw)
{
	struct rtw89_dev *rtwdev = hw->priv;

	rtw89_write8_mask(rtwdev, R_AX_GPIO8_15_FUNC_SEL, 0xf, 0x6); /* GPIO8 pin: WL_LED */
	rtw89_write32_set(rtwdev, R_AX_LED_CFG, BIT(21));            /* WL_LED function on (byte 0x4e bit 5) */
	rtw89_write32_clr(rtwdev, R_AX_LED_CFG, BIT(22) | GENMASK(18, 16)); /* LED2 mode 0: software */
}

void rtwd_led_set(struct ieee80211_hw *hw, bool on)
{
	rtw89_write32_mask(hw->priv, R_AX_LED_CFG, BIT(19), !on); /* LED2SV: 1 = dark on the TX20U Nano */
}
