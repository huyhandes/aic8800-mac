/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * lkpi USB core over libusb: async bulk URBs completed on one event thread,
 * synchronous control requests, and a probe harness that binds the driver.
 */
#include "lkpi_usb.h"
#include <libusb.h>
#include "../wifi_drv.h"
unsigned int geteuid(void); /* <unistd.h> clashes with the Linux uuid_t */
#include <pthread/qos.h>

struct usb_driver *lkpi_usb_driver;
static libusb_context *ctx;
/* URB refcounts, use counts and anchor lists; held only for bookkeeping, never across a callback */
static pthread_mutex_t ulock = PTHREAD_MUTEX_INITIALIZER;

static int errno_of(int r)
{
	switch (r) {
	case LIBUSB_ERROR_NO_DEVICE: return -ENODEV;
	case LIBUSB_ERROR_TIMEOUT: return -ETIMEDOUT;
	case LIBUSB_ERROR_PIPE: return -EPIPE;
	case LIBUSB_ERROR_OVERFLOW: return -EOVERFLOW;
	case LIBUSB_ERROR_NO_MEM: return -ENOMEM;
	case LIBUSB_ERROR_BUSY: return -EBUSY;
	case LIBUSB_ERROR_ACCESS: return -EACCES;
	case LIBUSB_ERROR_INVALID_PARAM: return -EINVAL;
	default: return -EIO;
	}
}

/* libusb transfer status -> the urb->status values Linux host controllers report */
static int status_of(enum libusb_transfer_status s)
{
	switch (s) {
	case LIBUSB_TRANSFER_COMPLETED: return 0;
	case LIBUSB_TRANSFER_TIMED_OUT: return -ETIME;
	case LIBUSB_TRANSFER_CANCELLED: return -ENOENT;
	case LIBUSB_TRANSFER_STALL: return -EPIPE;
	case LIBUSB_TRANSFER_NO_DEVICE: return -ENODEV;
	case LIBUSB_TRANSFER_OVERFLOW: return -EOVERFLOW;
	default: return -EPROTO;
	}
}

static pthread_t ev_th;
static pthread_cond_t zlp_cv = PTHREAD_COND_INITIALIZER;

static void *event_main(void *arg)
{
	ev_th = pthread_self();
	pthread_setname_np("lkpi-usb");
	for (;;)
		libusb_handle_events(ctx);
	return NULL;
}

static int init_err;

static void usb_init(void)
{
	pthread_attr_t a;
	pthread_t th;

	init_err = libusb_init_context(&ctx, NULL, 0);
	if (init_err)
		return;
	pthread_attr_init(&a);
	/* every RX/TX completion runs here: keep it on a P-core */
	pthread_attr_set_qos_class_np(&a, QOS_CLASS_USER_INTERACTIVE, 0);
	pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
	init_err = pthread_create(&th, &a, event_main, NULL) ? LIBUSB_ERROR_OTHER : 0;
	pthread_attr_destroy(&a);
}

static int usb_init_once(void)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;

	pthread_once(&once, usb_init);
	return init_err;
}

/* ---------- URBs ---------- */
struct urb *usb_alloc_urb(int iso_packets, gfp_t gfp)
{
	struct urb *u = calloc(1, sizeof(*u));

	if (!u)
		return NULL;
	u->xfer = libusb_alloc_transfer(0);
	if (!u->xfer) {
		free(u);
		return NULL;
	}
	INIT_LIST_HEAD(&u->anchor_list);
	pthread_cond_init(&u->done, NULL);
	u->refcount = 1;
	return u;
}

static void put_locked(struct urb *u)
{
	if (--u->refcount)
		return;
	libusb_free_transfer(u->xfer);
	pthread_cond_destroy(&u->done);
	free(u);
}

void usb_free_urb(struct urb *u)
{
	if (!u)
		return;
	pthread_mutex_lock(&ulock);
	put_locked(u);
	pthread_mutex_unlock(&ulock);
}

static void unanchor_locked(struct urb *u)
{
	struct usb_anchor *a = u->anchor;

	if (!a)
		return;
	list_del_init(&u->anchor_list);
	u->anchor = NULL;
	if (list_empty(&a->urb_list) && !a->busy)
		pthread_cond_broadcast(&a->empty);
	put_locked(u); /* the anchor's reference */
}

static void xfer_cb(struct libusb_transfer *x)
{
	struct urb *urb = x->user_data;
	int status = status_of(x->status);
	struct usb_anchor *a;

	pthread_mutex_lock(&ulock);
	if (x->length || !urb->transfer_buffer_length)
		urb->actual_length = x->actual_length; /* not the ZLP stage */
	if (urb->zlp_pending) {
		/* the data ended on a packet boundary: send the zero-length packet the device waits for */
		bool queued = false;

		urb->zlp_pending = false;
		if (!status && !urb->reject) {
			x->length = 0;
			queued = !libusb_submit_transfer(x);
			if (!queued)
				status = -EPROTO;
		}
		urb->dev->zlp_hold &= ~BIT(usb_pipeendpoint(urb->pipe)); /* the ZLP is queued, or never will be */
		pthread_cond_broadcast(&zlp_cv);
		if (queued) {
			pthread_mutex_unlock(&ulock);
			return;
		}
	}
	urb->in_flight = false;
	urb->status = status;
	if (!usb_pipein(urb->pipe)) {
		unsigned int ep = usb_pipeendpoint(urb->pipe);
		urb->dev->out_busy[ep]--;
		urb->dev->out_done_ns[ep] = lkpi_now_ns();
	}
	a = urb->anchor;
	if (a) {
		a->busy++;
		unanchor_locked(urb); /* our submit reference keeps urb alive */
	}
	pthread_mutex_unlock(&ulock);

	if (status == -ENODEV)
		__atomic_store_n(&urb->dev->gone, true, __ATOMIC_RELAXED);
	urb->complete(urb); /* may resubmit the URB */

	pthread_mutex_lock(&ulock);
	if (a && !--a->busy && list_empty(&a->urb_list))
		pthread_cond_broadcast(&a->empty);
	urb->use_count--;
	pthread_cond_broadcast(&urb->done);
	put_locked(urb);
	pthread_mutex_unlock(&ulock);
}

int usb_submit_urb(struct urb *urb, gfp_t gfp)
{
	struct usb_device *d = urb->dev;
	unsigned int ep, len = urb->transfer_buffer_length;
	bool in;
	u16 maxp;
	int r;

	if (!d || !d->handle || !urb->complete)
		return -EINVAL;
	if (__atomic_load_n(&d->gone, __ATOMIC_RELAXED))
		return -ENODEV;
	ep = usb_pipeendpoint(urb->pipe);
	in = usb_pipein(urb->pipe);
	maxp = d->ep_maxpacket[ep | (in ? 16 : 0)];

	pthread_mutex_lock(&ulock);
	/* macOS libusb has no LIBUSB_TRANSFER_ADD_ZERO_PACKET, so a ZLP goes out as its own transfer after the data.
	   A URB queued in between made the RTL8852BU merge two frames and stop its TX pipe for good.
	   Never on the event thread, which clears the hold (only RX resubmits run there) */
	while (!in && (d->zlp_hold & BIT(ep)) && !pthread_equal(pthread_self(), ev_th) &&
	       !__atomic_load_n(&d->gone, __ATOMIC_RELAXED))
		pthread_cond_wait(&zlp_cv, &ulock);
	if (urb->reject) {
		pthread_mutex_unlock(&ulock);
		return -EPERM;
	}
	if (urb->in_flight) {
		pthread_mutex_unlock(&ulock);
		return -EBUSY;
	}
	urb->in_flight = true;
	urb->use_count++;
	urb->refcount++;
	urb->status = -EINPROGRESS;
	urb->actual_length = 0;
	urb->zlp_pending = !in && (urb->transfer_flags & URB_ZERO_PACKET) && len && maxp && !(len % maxp);
	libusb_fill_bulk_transfer(urb->xfer, d->handle, ep | (in ? LIBUSB_ENDPOINT_IN : 0),
				  urb->transfer_buffer, len, xfer_cb, urb, 0);
	/* under the lock, so a racing usb_kill_urb either sees it in flight or blocks the submit */
	r = libusb_submit_transfer(urb->xfer);
	if (r) {
		urb->in_flight = false;
		urb->use_count--;
		urb->refcount--; /* the caller still holds one */
	} else if (!in) {
		if (!d->out_busy[ep]++)
			d->out_done_ns[ep] = lkpi_now_ns();
		if (urb->zlp_pending)
			d->zlp_hold |= BIT(ep);
	}
	/* a wedged RTL8852BU kept failing H2C submits with LIBUSB_ERROR_IO for 1.5 h while still
	   enumerated: treat a dead pipe as an unplug so a fresh worker rebinds the dongle */
	u16 *errs = &d->submit_errs[ep | (in ? 16 : 0)];
	*errs = r && r != LIBUSB_ERROR_BUSY ? *errs + 1 : 0;
	const bool dead = *errs >= 50;
	pthread_mutex_unlock(&ulock);
	if (r == LIBUSB_ERROR_NO_DEVICE || dead)
		__atomic_store_n(&d->gone, true, __ATOMIC_RELAXED);
	return r ? errno_of(r) : 0;
}

/* cancel and wait for the completion to finish; must not run on the lkpi-usb thread */
void usb_kill_urb(struct urb *urb)
{
	if (!urb)
		return;
	pthread_mutex_lock(&ulock);
	urb->reject++;
	if (urb->in_flight)
		libusb_cancel_transfer(urb->xfer); /* macOS aborts the whole pipe: fine, kills are teardown-only */
	while (urb->use_count)
		pthread_cond_wait(&urb->done, &ulock);
	urb->reject--;
	pthread_mutex_unlock(&ulock);
}

void init_usb_anchor(struct usb_anchor *a)
{
	INIT_LIST_HEAD(&a->urb_list);
	spin_lock_init(&a->lock);
	pthread_cond_init(&a->empty, NULL);
	a->busy = 0;
}

void usb_anchor_urb(struct urb *u, struct usb_anchor *a)
{
	pthread_mutex_lock(&ulock);
	u->refcount++;
	list_add_tail(&u->anchor_list, &a->urb_list);
	u->anchor = a;
	pthread_mutex_unlock(&ulock);
}

void usb_unanchor_urb(struct urb *u)
{
	pthread_mutex_lock(&ulock);
	unanchor_locked(u);
	pthread_mutex_unlock(&ulock);
}

void usb_kill_anchored_urbs(struct usb_anchor *a)
{
	pthread_mutex_lock(&ulock);
	while (!list_empty(&a->urb_list)) {
		struct urb *u = list_last_entry(&a->urb_list, struct urb, anchor_list);

		u->refcount++;
		pthread_mutex_unlock(&ulock);
		usb_kill_urb(u);
		pthread_mutex_lock(&ulock);
		if (u->anchor == a && !u->use_count)
			unanchor_locked(u); /* never submitted: would loop forever otherwise */
		put_locked(u);
	}
	while (a->busy)
		pthread_cond_wait(&a->empty, &ulock);
	pthread_mutex_unlock(&ulock);
}

int usb_control_msg(struct usb_device *d, unsigned int pipe, u8 request, u8 requesttype,
		    u16 value, u16 index, void *data, u16 size, int timeout_ms)
{
	int r;

	if (__atomic_load_n(&d->gone, __ATOMIC_RELAXED))
		return -ENODEV;
	r = libusb_control_transfer(d->handle, requesttype, request, value, index, data, size, timeout_ms);
	if (r == LIBUSB_ERROR_NO_DEVICE)
		__atomic_store_n(&d->gone, true, __ATOMIC_RELAXED);
	return r < 0 ? errno_of(r) : r;
}

/* ---------- probe harness ---------- */
struct binding {
	struct usb_device udev;
	struct usb_interface intf;
	struct usb_host_interface alt;
};

#define MATCH_VENDOR 0x0001
#define MATCH_PRODUCT 0x0002
#define MATCH_INT_CLASS 0x0080
#define MATCH_INT_SUBCLASS 0x0100
#define MATCH_INT_PROTOCOL 0x0200

static const struct usb_device_id *match(const struct libusb_device_descriptor *dd,
					  const struct libusb_interface_descriptor *id)
{
	for (const struct usb_device_id *m = lkpi_usb_driver->id_table; m->match_flags; m++) {
		if ((m->match_flags & MATCH_VENDOR) && m->idVendor != dd->idVendor)
			continue;
		if ((m->match_flags & MATCH_PRODUCT) && m->idProduct != dd->idProduct)
			continue;
		if ((m->match_flags & MATCH_INT_CLASS) && m->bInterfaceClass != id->bInterfaceClass)
			continue;
		if ((m->match_flags & MATCH_INT_SUBCLASS) && m->bInterfaceSubClass != id->bInterfaceSubClass)
			continue;
		if ((m->match_flags & MATCH_INT_PROTOCOL) && m->bInterfaceProtocol != id->bInterfaceProtocol)
			continue;
		return m;
	}
	return NULL;
}

static enum usb_device_speed speed_of(int s)
{
	switch (s) {
	case LIBUSB_SPEED_LOW: return USB_SPEED_LOW;
	case LIBUSB_SPEED_FULL: return USB_SPEED_FULL;
	case LIBUSB_SPEED_HIGH: return USB_SPEED_HIGH;
	case LIBUSB_SPEED_SUPER: return USB_SPEED_SUPER;
	case LIBUSB_SPEED_UNKNOWN: return USB_SPEED_UNKNOWN;
	default: return USB_SPEED_SUPER_PLUS;
	}
}

/* the matching device after the first `skip` ones and its interface 0, or NULL; *cd is set if a
   Realtek driver CD is present */
static libusb_device *find(const struct usb_device_id **idp, libusb_device **cd, int skip)
{
	libusb_device **list, *found = NULL;
	ssize_t n = libusb_get_device_list(ctx, &list);

	*cd = NULL;
	for (ssize_t i = 0; i < n && !found; i++) {
		struct libusb_device_descriptor dd;
		struct libusb_config_descriptor *cfg;

		if (libusb_get_device_descriptor(list[i], &dd))
			continue;
		if (dd.idVendor == 0x0bda && dd.idProduct == 0x1a2b && !*cd)
			*cd = libusb_ref_device(list[i]);
		if (libusb_get_active_config_descriptor(list[i], &cfg))
			continue;
		if (cfg->bNumInterfaces && cfg->interface[0].num_altsetting &&
		    (*idp = match(&dd, &cfg->interface[0].altsetting[0])) && skip-- == 0)
			found = libusb_ref_device(list[i]);
		libusb_free_config_descriptor(cfg);
	}
	if (n > 0)
		libusb_free_device_list(list, 1);
	return found;
}

/* Realtek "driver CD" mode: BOT reset, then SCSI START STOP UNIT (eject) flips it to Wi-Fi mode,
   the same CDB Windows' WifiAutoInstallSrv and usb_modeswitch send. macOS gates the mass-storage
   interface behind the per-user Removable Volumes permission (TCC), which a launchd daemon can never
   hold ("deny iokit-open-service IOUSBHostInterface"), so for the daemon the console user's cd-eject
   LaunchAgent sends it (lkpi_usb_eject_cd, cdcap.c) once the daemon has detached macOS's storage driver. */
static void eject_cd(libusb_device *dev)
{
	static const u8 inquiry[6] = { 0x12, 0, 0, 0, 36, 0 }, eject[6] = { 0x1b, 0, 0, 0, 0x02, 0 };
	libusb_device_handle *h;
	struct libusb_config_descriptor *cfg;
	u8 out = 0, in = 0, buf[36], csw[13];
	int t;

	if ((t = libusb_open(dev, &h))) {
		lkpi_log(3, "usb: driver CD open failed: %s\n", libusb_error_name(t));
		return;
	}
	libusb_set_auto_detach_kernel_driver(h, 1);
	if ((t = libusb_claim_interface(h, 0)) || (t = libusb_get_active_config_descriptor(dev, &cfg))) {
		lkpi_log(3, "usb: driver CD claim failed: %s\n", libusb_error_name(t));
		libusb_close(h);
		return;
	}
	const struct libusb_interface_descriptor *id = &cfg->interface[0].altsetting[0];
	for (int i = 0; i < id->bNumEndpoints; i++) {
		u8 ad = id->endpoint[i].bEndpointAddress;
		*(ad & LIBUSB_ENDPOINT_IN ? &in : &out) = ad;
	}
	libusb_free_config_descriptor(cfg);
	libusb_control_transfer(h, 0x21, 0xff, 0, 0, NULL, 0, 2000); /* Bulk-Only Mass Storage Reset */
	libusb_clear_halt(h, out);
	libusb_clear_halt(h, in);
	/* A timed-out earlier attempt leaves CSW/data queued on IN; the device NAKs new CBWs until it is read. */
	for (int i = 0; i < 8 && !libusb_bulk_transfer(h, in, buf, sizeof(buf), &t, 100); i++)
		;
	int r = 0;
	for (int k = 0; k < 2 && !r; k++) {
		const u8 *cdb = k ? eject : inquiry;
		int dlen = k ? 0 : sizeof(buf);
		u8 cbw[31] = { 'U', 'S', 'B', 'C', 0xa1 + k };
		put_unaligned_le32(dlen, cbw + 8);
		cbw[12] = dlen ? 0x80 : 0;
		cbw[14] = 6;
		memcpy(cbw + 15, cdb, 6);
		r = libusb_bulk_transfer(h, out, cbw, sizeof(cbw), &t, 2000);
		if (!r && dlen)
			r = libusb_bulk_transfer(h, in, buf, dlen, &t, 2000);
		if (!r)
			r = libusb_bulk_transfer(h, in, csw, sizeof(csw), &t, 2000);
		if (r)
			lkpi_log(3, "usb: driver CD %s failed: %s\n", k ? "eject" : "inquiry", libusb_error_name(r));
	}
	if (!r)
		lkpi_log(6, "ejected the Realtek driver CD, waiting for the Wi-Fi device\n");
	libusb_release_interface(h, 0);
	libusb_close(h);
}

int lkpi_detach_cd_driver(void); /* cdcap.c */

static void detach_cd(void)
{
	int r = lkpi_detach_cd_driver();

	if (r)
		lkpi_log(r > 0 ? 6 : 3, "usb: driver CD: detach macOS's driver for the cd-eject agent: %s\n",
			 r > 0 ? "done" : "failed");
}

/* The TX20U Nano has no USB 3 lanes, yet rtw89_usb_switch_mode tries them on every power-up: the chip drops
   off the bus for 5.4 s and comes back on USB 2 for a second probe. MATCH_CNT (R_AX_PAD_CTRL2 0xc4, bits
   15:8) = USB_SWITCH_DELAY (0xf) is rtw89's own "already tried, USB 2 port" mark, so it skips the switch. */
static void skip_usb3_switch(libusb_device_handle *h)
{
	u8 v[4];

	if (libusb_control_transfer(h, 0xc0, 0x05, 0x00c4, 0, v, 4, 500) == 4 && v[1] != 0x0f) {
		v[1] = 0x0f;
		libusb_control_transfer(h, 0x40, 0x05, 0x00c4, 0, v, 4, 500);
	}
}

static int bind_dev(libusb_device *dev, const struct usb_device_id *id, struct usb_interface **out)
{
	struct libusb_device_descriptor dd;
	struct libusb_config_descriptor *cfg;
	libusb_device_handle *h;
	struct binding *b;
	int r;

	*out = NULL;
	if (wifi_usb_lock(dev))
		return -EACCES; /* bound by another worker: the caller moves on to the next one */
	if ((r = libusb_open(dev, &h)))
		return errno_of(r);
	if ((r = libusb_claim_interface(h, 0))) {
		/* ACCESS: another usbwifid process drives this dongle; the caller moves on to the next one */
		lkpi_log(r == LIBUSB_ERROR_ACCESS ? 7 : 3, "usb: claim interface failed: %s\n", libusb_error_name(r));
		libusb_close(h);
		return errno_of(r);
	}
	b = calloc(1, sizeof(*b));
	if (!b || libusb_get_device_descriptor(dev, &dd) || libusb_get_active_config_descriptor(dev, &cfg)) {
		free(b);
		libusb_release_interface(h, 0);
		libusb_close(h);
		return -ENOMEM;
	}
	const struct libusb_interface_descriptor *ld = &cfg->interface[0].altsetting[0];
	b->alt.desc = (struct usb_interface_descriptor){
		ld->bLength, ld->bDescriptorType, ld->bInterfaceNumber, ld->bAlternateSetting,
		min_t(u8, ld->bNumEndpoints, ARRAY_SIZE(b->alt.endpoint)),
		ld->bInterfaceClass, ld->bInterfaceSubClass, ld->bInterfaceProtocol, ld->iInterface,
	};
	for (int i = 0; i < b->alt.desc.bNumEndpoints; i++) {
		const struct libusb_endpoint_descriptor *e = &ld->endpoint[i];
		struct usb_endpoint_descriptor *d = &b->alt.endpoint[i].desc;

		*d = (struct usb_endpoint_descriptor){ e->bLength, e->bDescriptorType, e->bEndpointAddress,
						       e->bmAttributes, cpu_to_le16(e->wMaxPacketSize), e->bInterval };
		b->udev.ep_maxpacket[usb_endpoint_num(d) | (usb_endpoint_dir_in(d) ? 16 : 0)] = usb_endpoint_maxp(d);
	}
	libusb_free_config_descriptor(cfg);
	b->udev.handle = h;
	b->udev.speed = speed_of(libusb_get_device_speed(dev));
	b->udev.descriptor = (struct usb_device_descriptor){ cpu_to_le16(dd.idVendor), cpu_to_le16(dd.idProduct),
							     cpu_to_le16(dd.bcdDevice) };
	b->udev.dev.init_name = lkpi_usb_driver->name;
	b->intf.dev.init_name = lkpi_usb_driver->name;
	b->intf.dev.parent = &b->udev.dev;
	b->intf.altsetting = b->intf.cur_altsetting = &b->alt;
	b->intf.num_altsetting = 1;
	b->intf.udev = &b->udev;
	lkpi_log(6, "usb: %04x:%04x bus %d port %d, %s speed\n", dd.idVendor, dd.idProduct,
		 libusb_get_bus_number(dev), libusb_get_port_number(dev),
		 b->udev.speed >= USB_SPEED_SUPER ? "super" : b->udev.speed == USB_SPEED_HIGH ? "high" : "full");
	/* shortcut: USB 2 only hardware by VID:PID, add a PID here when another one is known */
	if (dd.idVendor == 0x35bc && dd.idProduct == 0x0108)
		skip_usb3_switch(h);
	r = lkpi_usb_driver->probe(&b->intf, id);
	if (r || !usb_get_intfdata(&b->intf)) {
		libusb_release_interface(h, 0);
		libusb_close(h);
		free(b);
		return r;
	}
	*out = &b->intf;
	return 0;
}

static bool present(libusb_device *dev)
{
	libusb_device **list;
	ssize_t n = libusb_get_device_list(ctx, &list);
	bool r = false;

	for (ssize_t i = 0; i < n; i++)
		r |= list[i] == dev;
	if (n > 0)
		libusb_free_device_list(list, 1);
	return r;
}

struct usb_interface *lkpi_usb_probe(int timeout_ms)
{
	u64 end = lkpi_now_ns() + (u64)timeout_ms * NSEC_PER_MSEC;
	struct usb_interface *intf = NULL;
	int ejected = 0, switches = 0, skip = 0, r;

	if (!lkpi_usb_driver || usb_init_once())
		return NULL;
	for (;;) {
		const struct usb_device_id *id;
		libusb_device *cd, *dev = find(&id, &cd, skip);

		if (dev) {
			r = bind_dev(dev, id, &intf);
			if (r == -EACCES) {
				skip++;
				libusb_unref_device(dev);
				if (cd)
					libusb_unref_device(cd);
				continue;
			}
			if (intf || r || ++switches > 2) {
				if (r)
					lkpi_log(3, "usb: probe failed: %d\n", r);
				libusb_unref_device(dev);
				if (cd)
					libusb_unref_device(cd);
				return intf;
			}
			/* probe asked the chip to re-enumerate on its USB 3 lanes (rtw89_usb_switch_mode) */
			lkpi_log(6, "usb: waiting for the device to re-enumerate\n");
			for (u64 t = lkpi_now_ns() + 5 * NSEC_PER_SEC; present(dev) && lkpi_now_ns() < t;)
				lkpi_sleep_us(100000);
			end = max(end, lkpi_now_ns() + 10 * NSEC_PER_SEC);
			libusb_unref_device(dev);
		} else if ((skip = 0), cd && !geteuid()) { /* every match is taken: look for a driver CD */
			detach_cd();
		} else if (cd && ejected++ < 3) {
			eject_cd(cd);
			end = max(end, lkpi_now_ns() + 10 * NSEC_PER_SEC);
		}
		if (cd)
			libusb_unref_device(cd);
		if (lkpi_now_ns() >= end)
			return NULL;
		lkpi_sleep_us(200000);
	}
}

bool lkpi_usb_present(struct usb_interface *i)
{
	struct usb_device *d = i->udev;

	if (!lkpi_usb_gone(i) && !present(libusb_get_device(d->handle)))
		__atomic_store_n(&d->gone, true, __ATOMIC_RELAXED);
	/* under a speedtest the RTL8852BU stopped taking bulk-out data with the link still up: 186 TX URBs
	   sat queued for minutes and blackholed the Mac (no error, no completion). Rebind, as for an unplug */
	pthread_mutex_lock(&ulock);
	for (unsigned int ep = 0; ep < 16 && !d->gone; ep++)
		if (d->out_busy[ep] && lkpi_now_ns() - d->out_done_ns[ep] > 5 * NSEC_PER_SEC) {
			pr_err("usb: ep %u: %u TX URBs stuck for 5 s, rebinding the dongle\n", ep, d->out_busy[ep]);
			__atomic_store_n(&d->gone, true, __ATOMIC_RELAXED);
			pthread_cond_broadcast(&zlp_cv); /* a submit waiting on a ZLP that never goes out */
		}
	pthread_mutex_unlock(&ulock);
	return !lkpi_usb_gone(i);
}

void lkpi_usb_remove(struct usb_interface *intf)
{
	struct binding *b;

	if (!intf)
		return;
	b = container_of(intf, struct binding, intf);
	lkpi_usb_driver->disconnect(intf);
	libusb_release_interface(b->udev.handle, 0);
	libusb_close(b->udev.handle);
	free(b);
}
