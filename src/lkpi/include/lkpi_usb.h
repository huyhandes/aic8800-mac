/* SPDX-License-Identifier: BSD-3-Clause */
/* lkpi USB core: struct urb & friends backed by libusb (see ../usb.c) */
#ifndef LKPI_USB_H
#define LKPI_USB_H
#include "lkpi.h"
/* Linux-only HCD status; libusb never reports it, the value only has to be unique */
#define ECOMM 0x1000

enum usb_device_speed {
	USB_SPEED_UNKNOWN = 0, USB_SPEED_LOW, USB_SPEED_FULL, USB_SPEED_HIGH,
	USB_SPEED_WIRELESS, USB_SPEED_SUPER, USB_SPEED_SUPER_PLUS,
};
#define USB_DIR_OUT 0
#define USB_DIR_IN 0x80
#define USB_TYPE_VENDOR (0x02 << 5)
#define USB_RECIP_DEVICE 0x00
#define USB_ENDPOINT_NUMBER_MASK 0x0f
#define USB_ENDPOINT_DIR_MASK 0x80
#define USB_ENDPOINT_XFERTYPE_MASK 0x03
#define USB_ENDPOINT_XFER_BULK 2
#define USB_ENDPOINT_XFER_INT 3

struct usb_endpoint_descriptor {
	u8 bLength, bDescriptorType, bEndpointAddress, bmAttributes;
	__le16 wMaxPacketSize;
	u8 bInterval;
} __packed;
struct usb_interface_descriptor {
	u8 bLength, bDescriptorType, bInterfaceNumber, bAlternateSetting, bNumEndpoints;
	u8 bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol, iInterface;
} __packed;
struct usb_host_endpoint { struct usb_endpoint_descriptor desc; };
struct usb_host_interface {
	struct usb_interface_descriptor desc;
	struct usb_host_endpoint endpoint[32];
};
struct usb_device_descriptor { __le16 idVendor, idProduct, bcdDevice; };
struct libusb_device_handle;
struct usb_device {
	struct device dev;
	enum usb_device_speed speed;
	struct usb_device_descriptor descriptor;
	struct libusb_device_handle *handle;
	u16 ep_maxpacket[32]; /* index: endpoint number | (dir ? 16 : 0) */
	bool gone; /* a transfer saw LIBUSB_ERROR_NO_DEVICE, or a pipe stopped taking submits */
	u16 submit_errs[32]; /* consecutive failed submits, same index as ep_maxpacket */
};
struct usb_interface {
	struct device dev;
	struct usb_host_interface *altsetting;
	struct usb_host_interface *cur_altsetting;
	unsigned int num_altsetting;
	struct usb_device *udev;
};
static inline struct usb_device *interface_to_usbdev(struct usb_interface *i) { return i->udev; }
static inline void *usb_get_intfdata(struct usb_interface *i) { return i->dev.driver_data; }
static inline void usb_set_intfdata(struct usb_interface *i, void *d) { i->dev.driver_data = d; }
static inline struct usb_device *usb_get_dev(struct usb_device *d) { return d; }
static inline void usb_put_dev(struct usb_device *d) { }

struct usb_device_id {
	u16 match_flags, idVendor, idProduct;
	u8 bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol;
	kernel_ulong_t driver_info;
};
#define USB_DEVICE_ID_MATCH_DEVICE 0x0003
#define USB_DEVICE_ID_MATCH_INT_INFO 0x0380
#define USB_DEVICE_AND_INTERFACE_INFO(vend, prod, cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_INT_INFO | USB_DEVICE_ID_MATCH_DEVICE, \
	.idVendor = (vend), .idProduct = (prod), \
	.bInterfaceClass = (cl), .bInterfaceSubClass = (sc), .bInterfaceProtocol = (pr)
#define USB_DEVICE(vend, prod) .match_flags = USB_DEVICE_ID_MATCH_DEVICE, .idVendor = (vend), .idProduct = (prod)

struct usb_driver {
	const char *name;
	int (*probe)(struct usb_interface *intf, const struct usb_device_id *id);
	void (*disconnect)(struct usb_interface *intf);
	int (*suspend)(struct usb_interface *intf, int message);
	int (*resume)(struct usb_interface *intf);
	const struct usb_device_id *id_table;
	bool disable_hub_initiated_lpm;
	bool supports_autosuspend;
	struct { const struct attribute_group **dev_groups; } driver;
};
extern struct usb_driver *lkpi_usb_driver;
#define module_usb_driver(drv) \
	__attribute__((constructor)) static void __lkpi_register_##drv(void) { lkpi_usb_driver = &(drv); }

/* pipes: endpoint number + direction + type packed like Linux */
#define PIPE_CONTROL 2
#define PIPE_BULK 3
#define __lkpi_pipe(type, ep, in) (((type) << 30) | ((ep) << 15) | ((in) ? USB_DIR_IN : 0))
#define usb_sndctrlpipe(d, ep) __lkpi_pipe(PIPE_CONTROL, ep, 0)
#define usb_rcvctrlpipe(d, ep) __lkpi_pipe(PIPE_CONTROL, ep, 1)
#define usb_sndbulkpipe(d, ep) __lkpi_pipe(PIPE_BULK, ep, 0)
#define usb_rcvbulkpipe(d, ep) __lkpi_pipe(PIPE_BULK, ep, 1)
#define usb_pipeendpoint(p) (((p) >> 15) & 0xf)
#define usb_pipein(p) ((p) & USB_DIR_IN)

static inline int usb_endpoint_num(const struct usb_endpoint_descriptor *e) { return e->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK; }
static inline int usb_endpoint_dir_in(const struct usb_endpoint_descriptor *e) { return (e->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_DIR_IN; }
static inline int usb_endpoint_dir_out(const struct usb_endpoint_descriptor *e) { return !usb_endpoint_dir_in(e); }
static inline int usb_endpoint_xfer_bulk(const struct usb_endpoint_descriptor *e) { return (e->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_BULK; }
static inline int usb_endpoint_maxp(const struct usb_endpoint_descriptor *e) { return le16_to_cpu(e->wMaxPacketSize) & 0x7ff; }

#define URB_ZERO_PACKET 0x0040
struct urb;
typedef void (*usb_complete_t)(struct urb *);
struct usb_anchor {
	struct list_head urb_list;
	spinlock_t lock;
	pthread_cond_t empty;
	int busy; /* completions of unanchored URBs still running */
};
struct urb {
	struct list_head anchor_list;
	struct usb_anchor *anchor;
	struct usb_device *dev;
	unsigned int pipe;
	unsigned int transfer_flags;
	int status;
	void *transfer_buffer;
	u32 transfer_buffer_length;
	u32 actual_length;
	void *context;
	usb_complete_t complete;
	/* lkpi private */
	struct libusb_transfer *xfer;
	int refcount;
	int use_count; /* submitted and completion not yet finished */
	int reject;    /* usb_kill_urb in progress: refuse resubmits */
	bool in_flight; /* owned by libusb */
	bool zlp_pending;
	pthread_cond_t done;
};
struct urb *usb_alloc_urb(int iso_packets, gfp_t gfp);
void usb_free_urb(struct urb *urb);
static inline void usb_fill_bulk_urb(struct urb *u, struct usb_device *d, unsigned int pipe,
				     void *buf, int len, usb_complete_t fn, void *ctx)
{
	u->dev = d; u->pipe = pipe; u->transfer_buffer = buf; u->transfer_buffer_length = len;
	u->complete = fn; u->context = ctx;
}
int usb_submit_urb(struct urb *urb, gfp_t gfp);
void usb_kill_urb(struct urb *urb);
void init_usb_anchor(struct usb_anchor *a);
void usb_anchor_urb(struct urb *urb, struct usb_anchor *a);
void usb_unanchor_urb(struct urb *urb);
void usb_kill_anchored_urbs(struct usb_anchor *a);
int usb_control_msg(struct usb_device *d, unsigned int pipe, u8 request, u8 requesttype,
		    u16 value, u16 index, void *data, u16 size, int timeout_ms);

/* harness: bind lkpi_usb_driver to the first matching device (ejects a Realtek driver CD first) */
struct usb_interface *lkpi_usb_probe(int timeout_ms);
void lkpi_usb_remove(struct usb_interface *intf);
static inline bool lkpi_usb_gone(const struct usb_interface *i) { return __atomic_load_n(&i->udev->gone, __ATOMIC_RELAXED); }
/* also checks the bus: a stalled driver has no transfer in flight to report the unplug */
bool lkpi_usb_present(struct usb_interface *i);
#endif
