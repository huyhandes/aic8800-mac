// SPDX-License-Identifier: BSD-3-Clause
/* Apple frameworks kept out of usb.c, whose Linux-style headers clash with them */
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

static io_service_t cd_device(void)
{
	CFMutableDictionaryRef m = IOServiceMatching("IOUSBHostDevice");
	int v = 0x0bda, p = 0x1a2b;
	CFNumberRef nv = CFNumberCreate(NULL, kCFNumberIntType, &v), np = CFNumberCreate(NULL, kCFNumberIntType, &p);

	CFDictionarySetValue(m, CFSTR(kUSBVendorID), nv);
	CFDictionarySetValue(m, CFSTR(kUSBProductID), np);
	CFRelease(nv);
	CFRelease(np);
	return IOServiceGetMatchingService(kIOMainPortDefault, m);
}

/* the CD's interface; -1 while it is still being configured, 0 once no CD is left */
static io_service_t cd_interface(void)
{
	io_service_t dev = cd_device(), s = 0;
	io_iterator_t it;

	if (!dev)
		return 0;
	if (!IORegistryEntryGetChildIterator(dev, kIOServicePlane, &it)) {
		while ((s = IOIteratorNext(it)) && !IOObjectConformsTo(s, "IOUSBHostInterface"))
			IOObjectRelease(s);
		IOObjectRelease(it);
	}
	IOObjectRelease(dev);
	return s ? s : (io_service_t)-1;
}

/* Root half: macOS's mass-storage driver holds the CD's interface (looping on READ TOC timeouts) and refuses
   to give it up, even to USBInterfaceOpenSeize (kIOReturnExclusiveAccess). Only root may drop it, by
   re-enumerating with capture through a short-lived device client; it doesn't re-match after. 1 = detached,
   0 = nothing attached, <0 = IOKit error. */
int lkpi_detach_cd_driver(void)
{
	io_service_t dev = cd_device();
	io_iterator_t it;
	io_registry_entry_t e;
	bool driven = false;
	int r = 0;

	if (!dev)
		return 0;
	if (!IORegistryEntryCreateIterator(dev, kIOServicePlane, kIORegistryIterateRecursively, &it)) {
		while ((e = IOIteratorNext(it))) {
			driven |= !IOObjectConformsTo(e, "IOUSBHostInterface") && !IOObjectConformsTo(e, "IOUserClient");
			IOObjectRelease(e);
		}
		IOObjectRelease(it);
	}
	if (driven) {
		IOCFPlugInInterface **pi;
		IOUSBDeviceInterface650 **d = NULL;
		SInt32 score;

		r = IOCreatePlugInInterfaceForService(dev, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &pi, &score);
		if (!r) {
			(*pi)->QueryInterface(pi, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID650), (LPVOID *)&d);
			IODestroyPlugInInterface(pi);
		}
		if (d) {
			r = (*d)->USBDeviceReEnumerate(d, kUSBReEnumerateCaptureDeviceMask);
			(*d)->Release(d);
		}
		r = r ? -((r & 0xfff) ? (r & 0xfff) : EIO) : d ? 1 : -1; /* never 0 ("nothing attached") on error */
	}
	IOObjectRelease(dev);
	return r;
}

/* BOT CBW carrying SCSI START STOP UNIT (eject), the CDB Windows' WifiAutoInstallSrv sends */
static kern_return_t eject(io_service_t s)
{
	IOCFPlugInInterface **pi;
	IOUSBInterfaceInterface300 **i = NULL;
	SInt32 score;
	kern_return_t r = IOCreatePlugInInterfaceForService(s, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID,
							    &pi, &score);
	if (r)
		return r;
	(*pi)->QueryInterface(pi, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID300), (LPVOID *)&i);
	IODestroyPlugInInterface(pi);
	if (!i)
		return kIOReturnUnsupported;
	if (!(r = (*i)->USBInterfaceOpenSeize(i))) {
		UInt8 n = 0, out = 0, in = 0, csw[13];
		UInt8 cbw[31] = { 'U', 'S', 'B', 'C', 0xa1, [14] = 6, [15] = 0x1b, [19] = 0x02 };
		UInt32 len = sizeof(csw);

		(*i)->GetNumEndpoints(i, &n);
		for (UInt8 k = 1; k <= n; k++) {
			UInt8 dir, num, type, intv;
			UInt16 mps;
			if (!(*i)->GetPipeProperties(i, k, &dir, &num, &type, &mps, &intv) && type == kUSBBulk)
				*(dir == kUSBIn ? &in : &out) = k;
		}
		if (out && in) { /* the recipe that switches it: BOT reset, clear halts, drain, INQUIRY, then the eject.
				    Without INQUIRY the eject CBW times out (0xe0004051) on a CD macOS's driver has poked */
			UInt8 num = 0, buf[512];
			UInt8 inq[31] = { 'U', 'S', 'B', 'C', 0xa2, [8] = 36, [12] = 0x80, [14] = 6, [15] = 0x12, [19] = 36 };
			UInt32 l = sizeof(buf);
			(*i)->GetInterfaceNumber(i, &num);
			IOUSBDevRequestTO rq = { .bmRequestType = 0x21, .bRequest = 0xff, .wIndex = num,
						 .noDataTimeout = 1000, .completionTimeout = 1000 };
			(*i)->ControlRequestTO(i, 0, &rq);
			(*i)->ClearPipeStallBothEnds(i, out);
			(*i)->ClearPipeStallBothEnds(i, in);
			(*i)->ReadPipeTO(i, in, buf, &l, 300, 300); /* a stale CSW left by an earlier try */
			if (!(*i)->WritePipeTO(i, out, inq, sizeof(inq), 2000, 2000)) {
				l = 36;
				(*i)->ReadPipeTO(i, in, buf, &l, 2000, 2000);
				l = sizeof(csw);
				(*i)->ReadPipeTO(i, in, csw, &l, 2000, 2000);
			}
		}
		r = !out || !in ? kIOReturnNoDevice : (*i)->WritePipeTO(i, out, cbw, sizeof(cbw), 2000, 2000);
		if (!r) /* the CSW may never come: the device can drop off the bus mid-command */
			(*i)->ReadPipeTO(i, in, csw, &len, 2000, 2000);
		(*i)->USBInterfaceClose(i);
	}
	(*i)->Release(i);
	return r;
}

/* Console-user half of plug-in (the com.usbwifi.cdswitch LaunchAgent): macOS gates the CD's interface
   behind the per-user Removable Volumes permission, which a launchd daemon can never hold. IOKit's interface
   client, not libusb: libusb lists a device only through its device client, which the kernel refuses to
   non-root callers after the root half's capture (NeedsDeviceAccessEntitlement). 0 once no CD is left. */
int lkpi_usb_eject_cd(int timeout_ms)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	time_t end = t.tv_sec + (timeout_ms + 999) / 1000;

	for (;;) {
		io_service_t s = cd_interface();
		if (!s)
			return 0;
		if (s != (io_service_t)-1) {
			kern_return_t r = eject(s);
			IOObjectRelease(s);
			if (r)
				fprintf(stderr, "cd-eject: 0x%x\n", r);
		}
		clock_gettime(CLOCK_MONOTONIC, &t);
		if (t.tv_sec >= end)
			return -ETIMEDOUT;
		usleep(1000000);
	}
}
