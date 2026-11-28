/* SPDX-License-Identifier: BSD-3-Clause */
/* the core over two stand-in drivers: any struct wifi_drv binds without core changes, and a driver that
   fails to bind is tried last by the next worker, so it cannot keep another chip from binding */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "usbwifi_core.h"
#include "wifi_drv.h"

static int stuck_open(const struct wifi_drv_events *ev, struct wifi_drv_info *info, int t) { return -EIO; }
static int fake_open(const struct wifi_drv_events *ev, struct wifi_drv_info *info, int t)
{
	snprintf(info->chip, sizeof(info->chip), "FAKE3");
	info->mac[0] = 2;
	return 0;
}
static int scans;
static int fake_scan(const uint8_t *s, uint8_t l, const uint16_t *f, int n) { scans++; return 0; }
static int nop_connect(const struct wifi_connect_params *p) { return 0; }
static void nop_disconnect(uint16_t r) {}
static int nop_key(bool pw, uint8_t idx, uint32_t c, const uint8_t *k, uint8_t l) { return 0; }
static int nop_auth(bool on) { return 0; }
static int nop_tx(const uint8_t *e, size_t l) { return 0; }

/* the core's driver table names these two; here they stand for "a stuck chip" and "a new chip" */
const struct wifi_drv wifi_drv_aic8800 = { "stuck", stuck_open, fake_scan, nop_connect, nop_disconnect,
					   nop_key, nop_auth, nop_tx, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
const struct wifi_drv wifi_drv_rtw89 = { "fake3", fake_open, fake_scan, nop_connect, nop_disconnect,
					 nop_key, nop_auth, nop_tx, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

static int child(void)
{
	pid_t p = fork();
	if (p == 0) {
		io_connect_t c;
		io_service_t s;
		if (wifi_open(&c, &s, true, NULL) != 0) _exit(2);
		_exit(strcmp(wifi_chip_name(), "FAKE3") == 0 && wifi_start_scan(c, NULL, 0, NULL, 0) == KERN_SUCCESS &&
		      scans == 1 && wifi_set_power_save(true) == -EOPNOTSUPP ? 0 : 3);
	}
	int st;
	assert(p > 0 && waitpid(p, &st, 0) == p && WIFEXITED(st));
	return WEXITSTATUS(st);
}

int main(void)
{
	setenv("AICD_NO_NET", "1", 1);
	mkdir(WIFI_RUN_DIR, 0755);
	unlink(WIFI_RUN_DIR "/bad-driver");
	assert(child() == 1);  /* the stuck driver is first: the worker exits ... */
	FILE *f = fopen(WIFI_RUN_DIR "/bad-driver", "r");
	unsigned bad = 9;
	assert(f && fscanf(f, "%u", &bad) == 1 && bad == 0);
	fclose(f);
	assert(child() == 0);  /* ... and the next one tries the other driver first and binds it */
	puts("drv_contract_test ok");
	return 0;
}
