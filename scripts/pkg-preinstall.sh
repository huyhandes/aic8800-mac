#!/bin/bash
# core pkg preinstall: a driver left unticked this time must not linger from an earlier install
rm -rf "/Library/Application Support/USB Wifi/fw/aic8800D80" "/Library/Application Support/USB Wifi/fw/rtw89"
exit 0
