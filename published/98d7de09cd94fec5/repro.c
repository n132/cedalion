// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <linux/lwtunnel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/seg6_local.h>
#include <linux/virtio_net.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef VIRTIO_NET_HDR_GSO_UDP_L4
#define VIRTIO_NET_HDR_GSO_UDP_L4 5
#endif
#ifndef TUN_F_USO4
#define TUN_F_USO4 0x20
#define TUN_F_USO6 0x40
#endif

#define VRF_TABLE 100
#define UDP_PORT 5555
#define PAYLOAD_LEN 400
#define GSO_SIZE 100
#define NLBUFSZ 4096

static int nl_fd;
static uint32_t nl_seq;

static void die(const char *what)
{
	perror(what);
	exit(1);
}

static void write_file(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY);
	size_t len = strlen(value);

	if (fd < 0)
		die(path);
	if (write(fd, value, len) != (ssize_t)len)
		die(path);
	close(fd);
}

static void enter_user_netns(void)
{
	char map[64];
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
		die("unshare(CLONE_NEWUSER|CLONE_NEWNET)");
	snprintf(map, sizeof(map), "0 %u 1\n", uid);
	write_file("/proc/self/uid_map", map);
	write_file("/proc/self/setgroups", "deny\n");
	snprintf(map, sizeof(map), "0 %u 1\n", gid);
	write_file("/proc/self/gid_map", map);
}

static int addattr(struct nlmsghdr *nlh, size_t maxlen, int type,
		   const void *data, size_t len)
{
	size_t alen = RTA_LENGTH(len);
	size_t newlen = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(alen);
	struct rtattr *rta;

	if (newlen > maxlen) {
		errno = EMSGSIZE;
		return -1;
	}
	rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = alen;
	if (len)
		memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = newlen;
	return 0;
}

static struct rtattr *nest_start(struct nlmsghdr *nlh, size_t maxlen, int type)
{
	struct rtattr *nest;

	nest = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	if (addattr(nlh, maxlen, type, NULL, 0))
		return NULL;
	return nest;
}

static void nest_end(struct nlmsghdr *nlh, struct rtattr *nest)
{
	nest->rta_len = (char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len) -
			(char *)nest;
}

static void nl_talk(struct nlmsghdr *nlh)
{
	char buf[NLBUFSZ];
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct iovec iov = { .iov_base = nlh, .iov_len = nlh->nlmsg_len };
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t n;

	nlh->nlmsg_seq = ++nl_seq;
	if (sendmsg(nl_fd, &msg, 0) < 0)
		die("sendmsg(netlink)");

	for (;;) {
		struct nlmsghdr *h;
		int rem;

		n = recv(nl_fd, buf, sizeof(buf), 0);
		if (n < 0)
			die("recv(netlink)");
		rem = n;
		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, rem);
		     h = NLMSG_NEXT(h, rem)) {
			struct nlmsgerr *e;

			if (h->nlmsg_seq != nl_seq || h->nlmsg_type != NLMSG_ERROR)
				continue;
			e = NLMSG_DATA(h);
			if (e->error) {
				errno = -e->error;
				die("rtnetlink ACK");
			}
			return;
		}
	}
}

static void create_vrf(void)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[512];
	} req = { 0 };
	struct rtattr *li, *data;
	uint32_t table = VRF_TABLE;
	const char name[] = "vrf0";
	const char kind[] = "vrf";

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifi));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE |
				NLM_F_EXCL;
	req.ifi.ifi_family = AF_UNSPEC;
	if (addattr(&req.nlh, sizeof(req), IFLA_IFNAME, name, sizeof(name)))
		die("IFLA_IFNAME");
	li = nest_start(&req.nlh, sizeof(req), IFLA_LINKINFO);
	if (!li || addattr(&req.nlh, sizeof(req), IFLA_INFO_KIND, kind,
			   sizeof(kind)))
		die("IFLA_LINKINFO");
	data = nest_start(&req.nlh, sizeof(req), IFLA_INFO_DATA);
	if (!data || addattr(&req.nlh, sizeof(req), IFLA_VRF_TABLE,
			     &table, sizeof(table)))
		die("IFLA_INFO_DATA");
	nest_end(&req.nlh, data);
	nest_end(&req.nlh, li);
	nl_talk(&req.nlh);
}

static void link_up(int ifindex)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req = { 0 };

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifi));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = ifindex;
	req.ifi.ifi_flags = IFF_UP;
	req.ifi.ifi_change = IFF_UP;
	nl_talk(&req.nlh);
}

static void add_local_v4_route(int vrf_ifindex)
{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		char attrs[256];
	} req = { 0 };
	struct in_addr dst;
	uint32_t oif = vrf_ifindex;

	inet_pton(AF_INET, "10.0.0.2", &dst);
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rtm));
	req.nlh.nlmsg_type = RTM_NEWROUTE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE |
				NLM_F_EXCL;
	req.rtm.rtm_family = AF_INET;
	req.rtm.rtm_dst_len = 32;
	req.rtm.rtm_table = VRF_TABLE;
	req.rtm.rtm_protocol = RTPROT_STATIC;
	req.rtm.rtm_scope = RT_SCOPE_HOST;
	req.rtm.rtm_type = RTN_LOCAL;
	if (addattr(&req.nlh, sizeof(req), RTA_DST, &dst, sizeof(dst)) ||
	    addattr(&req.nlh, sizeof(req), RTA_OIF, &oif, sizeof(oif)))
		die("local route attributes");
	nl_talk(&req.nlh);
}

static void add_end_dt4_route(int vrf_ifindex)
{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		char attrs[512];
	} req = { 0 };
	struct in6_addr sid;
	struct rtattr *encap;
	uint32_t oif = vrf_ifindex;
	uint32_t action = SEG6_LOCAL_ACTION_END_DT4;
	uint32_t table = VRF_TABLE;
	uint16_t encap_type = LWTUNNEL_ENCAP_SEG6_LOCAL;

	inet_pton(AF_INET6, "fc00::1", &sid);
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rtm));
	req.nlh.nlmsg_type = RTM_NEWROUTE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE |
				NLM_F_EXCL;
	req.rtm.rtm_family = AF_INET6;
	req.rtm.rtm_dst_len = 128;
	req.rtm.rtm_table = RT_TABLE_MAIN;
	req.rtm.rtm_protocol = RTPROT_STATIC;
	req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
	req.rtm.rtm_type = RTN_UNICAST;
	if (addattr(&req.nlh, sizeof(req), RTA_DST, &sid, sizeof(sid)) ||
	    addattr(&req.nlh, sizeof(req), RTA_OIF, &oif, sizeof(oif)))
		die("End.DT4 route base attributes");
	encap = nest_start(&req.nlh, sizeof(req), RTA_ENCAP);
	if (!encap ||
	    addattr(&req.nlh, sizeof(req), SEG6_LOCAL_ACTION, &action,
		    sizeof(action)) ||
	    addattr(&req.nlh, sizeof(req), SEG6_LOCAL_VRFTABLE, &table,
		    sizeof(table)))
		die("End.DT4 encap attributes");
	nest_end(&req.nlh, encap);
	if (addattr(&req.nlh, sizeof(req), RTA_ENCAP_TYPE, &encap_type,
		    sizeof(encap_type)))
		die("RTA_ENCAP_TYPE");
	nl_talk(&req.nlh);
}

static void enable_vrf_strict_mode(void)
{
	const char one[] = "1\n";
	int fd = open("/proc/sys/net/vrf/strict_mode", O_WRONLY);

	if (fd < 0)
		die("open(vrf strict_mode)");
	if (write(fd, one, sizeof(one) - 1) != sizeof(one) - 1)
		die("write(vrf strict_mode)");
	close(fd);
}

static int create_tun(void)
{
	struct ifreq ifr = { 0 };
	unsigned int offloads = TUN_F_CSUM | TUN_F_USO4 | TUN_F_USO6;
	int fd = open("/dev/net/tun", O_RDWR);

	if (fd < 0)
		die("open(/dev/net/tun)");
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
	strcpy(ifr.ifr_name, "tun0");
	if (ioctl(fd, TUNSETIFF, &ifr) < 0)
		die("TUNSETIFF");
	if (ioctl(fd, TUNSETOFFLOAD, offloads) < 0)
		die("TUNSETOFFLOAD");
	link_up(if_nametoindex(ifr.ifr_name));
	return fd;
}

static int create_udp_socket(void)
{
	struct sockaddr_in addr = { 0 };
	const char dev[] = "vrf0";
	int one = 1;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		die("socket(AF_INET, UDP)");
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, sizeof(dev)) < 0)
		die("SO_BINDTODEVICE");
	if (setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one)) < 0)
		die("IP_FREEBIND");
	addr.sin_family = AF_INET;
	addr.sin_port = htons(UDP_PORT);
	inet_pton(AF_INET, "10.0.0.2", &addr.sin_addr);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("bind(UDP)");
	return fd;
}

static uint16_t checksum(const void *data, size_t len)
{
	const uint16_t *p = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
	if (len)
		sum += *(const uint8_t *)p;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

static uint16_t udp_pseudo_seed(uint32_t src, uint32_t dst, uint16_t udp_len)
{
	struct {
		uint32_t src;
		uint32_t dst;
		uint8_t zero;
		uint8_t proto;
		uint16_t len;
	} __attribute__((packed)) ph = {
		.src = src,
		.dst = dst,
		.proto = IPPROTO_UDP,
		.len = htons(udp_len),
	};

	return checksum(&ph, sizeof(ph));
}

static void inject_packet(int tun_fd)
{
	struct {
		struct virtio_net_hdr vh;
		struct ipv6hdr outer;
		struct iphdr inner;
		struct udphdr udp;
		unsigned char payload[PAYLOAD_LEN];
	} __attribute__((packed)) pkt = { 0 };
	ssize_t n;

	pkt.vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	pkt.vh.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4;
	pkt.vh.hdr_len = sizeof(pkt.outer) + sizeof(pkt.inner) + sizeof(pkt.udp);
	pkt.vh.gso_size = GSO_SIZE;
	pkt.vh.csum_start = sizeof(pkt.outer) + sizeof(pkt.inner);
	pkt.vh.csum_offset = offsetof(struct udphdr, check);

	pkt.outer.version = 6;
	pkt.outer.payload_len = htons(sizeof(pkt.inner) + sizeof(pkt.udp) +
				       sizeof(pkt.payload));
	pkt.outer.nexthdr = IPPROTO_IPIP;
	pkt.outer.hop_limit = 64;
	inet_pton(AF_INET6, "fc00::2", &pkt.outer.saddr);
	inet_pton(AF_INET6, "fc00::1", &pkt.outer.daddr);

	pkt.inner.version = 4;
	pkt.inner.ihl = 5;
	pkt.inner.tot_len = htons(sizeof(pkt.inner) + sizeof(pkt.udp) +
				      sizeof(pkt.payload));
	pkt.inner.id = htons(0x1234);
	pkt.inner.ttl = 64;
	pkt.inner.protocol = IPPROTO_UDP;
	inet_pton(AF_INET, "10.0.0.1", &pkt.inner.saddr);
	inet_pton(AF_INET, "10.0.0.2", &pkt.inner.daddr);
	pkt.inner.check = checksum(&pkt.inner, sizeof(pkt.inner));

	pkt.udp.source = htons(4444);
	pkt.udp.dest = htons(UDP_PORT);
	pkt.udp.len = htons(sizeof(pkt.udp) + sizeof(pkt.payload));
	pkt.udp.check = udp_pseudo_seed(pkt.inner.saddr, pkt.inner.daddr,
					 sizeof(pkt.udp) + sizeof(pkt.payload));
	memset(pkt.payload, 0x41, sizeof(pkt.payload));

	n = write(tun_fd, &pkt, sizeof(pkt));
	if (n < 0)
		die("write(tun GSO packet)");
}

int main(void)
{
	struct sockaddr_nl local = { .nl_family = AF_NETLINK };
	int vrf_ifindex, tun_fd, udp_fd;

	enter_user_netns();
	nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_fd < 0)
		die("socket(NETLINK_ROUTE)");
	if (bind(nl_fd, (struct sockaddr *)&local, sizeof(local)) < 0)
		die("bind(NETLINK_ROUTE)");

	create_vrf();
	vrf_ifindex = if_nametoindex("vrf0");
	if (!vrf_ifindex)
		die("if_nametoindex(vrf0)");
	link_up(vrf_ifindex);
	enable_vrf_strict_mode();
	add_local_v4_route(vrf_ifindex);
	add_end_dt4_route(vrf_ifindex);
	udp_fd = create_udp_socket();
	tun_fd = create_tun();

	printf("ready: vrf ifindex=%d, UDP fd=%d, TUN fd=%d\n",
	       vrf_ifindex, udp_fd, tun_fd);
	printf("injecting 256 IPv6/IPIP inner UDP GSO packets\n");
	fflush(stdout);
	for (int i = 0; i < 256; i++) {
		inject_packet(tun_fd);
		usleep(10000);
	}
	sleep(2);
	printf("injection loop completed; inspect the kernel log for nonfatal sanitizer reports\n");
	return 0;
}
