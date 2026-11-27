#!/bin/bash
# core pkg preinstall: a driver left unticked this time must not linger from an earlier install
rm -f /Library/PrivilegedHelperTools/aic8800-mac/aic8800_fwload
rm -rf "/Library/Application Support/AIC8800/fw/aic8800D80" "/Library/Application Support/AIC8800/fw/rtw89"
exit 0
