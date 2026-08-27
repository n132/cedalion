// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>

#ifndef PACKET_VNET_HDR
#define PACKET_VNET_HDR 15
#endif

struct vnet_hdr {
	unsigned char  flags;
	unsigned char  gso_type;
	unsigned short hdr_len;
	unsigned short gso_size;
	unsigned short csum_start;
	unsigned short csum_offset;
} __attribute__((packed));

#define BIG_MTU   9000

static int if_get_index(int s, const char *name)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
		return -1;
	return ifr.ifr_ifindex;
}

static int if_up(int s, const char *name)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "[-] SIOCGIFFLAGS %s: %s\n", name, strerror(errno));
		return -1;
	}
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "[-] SIOCSIFFLAGS %s: %s\n", name, strerror(errno));
		return -1;
	}
	return 0;
}

static int if_set_mtu(int s, const char *name, int mtu)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	ifr.ifr_mtu = mtu;
	if (ioctl(s, SIOCSIFMTU, &ifr) < 0) {
		fprintf(stderr, "[-] SIOCSIFMTU %s=%d: %s\n", name, mtu, strerror(errno));
		return -1;
	}
	return 0;
}

static int if_get_mtu(int s, const char *name)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(s, SIOCGIFMTU, &ifr) < 0)
		return -1;
	return ifr.ifr_mtu;
}

static void dump_ifaces(void)
{
	char buf[4096];
	int fd, n;

	fd = open("/proc/net/dev", O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = 0;
		fprintf(stderr, "[*] /proc/net/dev:\n%s\n", buf);
	}
	close(fd);
}

static void cat_file(const char *path)
{
	char buf[512];
	int fd, n;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "[*] %s: %s\n", path, strerror(errno));
		return;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	if (n >= 0) {
		buf[n] = 0;
		fprintf(stderr, "[*] %s = %s", path, buf);
		if (n == 0 || buf[n - 1] != '\n')
			fprintf(stderr, "\n");
	}
	close(fd);
}

static void dump_iface_stats(const char *name)
{
	char buf[8192];
	char *p;
	int fd, n;

	fd = open("/proc/net/dev", O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = 0;
	for (p = strtok(buf, "\n"); p; p = strtok(NULL, "\n")) {
		char *q = p;
		while (*q == ' ')
			q++;
		if (!strncmp(q, name, strlen(name)) && q[strlen(name)] == ':')
			fprintf(stderr, "[*] stats: %s\n", q);
	}
}

#ifndef SIOCETHTOOL
#define SIOCETHTOOL 0x8946
#endif
#define ETHTOOL_GSG 0x00000018

static void dump_sg(int s, const char *name)
{
	struct ifreq ifr;
	struct {
		unsigned int cmd;
		unsigned int data;
	} ev;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	ev.cmd = ETHTOOL_GSG;
	ev.data = 0;
	ifr.ifr_data = (void *)&ev;
	if (ioctl(s, SIOCETHTOOL, &ifr) < 0) {
		fprintf(stderr, "[*] %s scatter-gather: ioctl failed (%s)\n",
			name, strerror(errno));
		return;
	}
	fprintf(stderr, "[*] %s NETIF_F_SG = %u\n", name, ev.data);
}

static int send_paged_frame(int idx, int len)
{
	struct sockaddr_ll sll;
	struct vnet_hdr vh;
	unsigned char *buf;
	int pf, one = 1;
	ssize_t r;

	pf = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (pf < 0) {
		fprintf(stderr, "[-] socket(AF_PACKET): %s\n", strerror(errno));
		return -1;
	}
	if (setsockopt(pf, SOL_PACKET, PACKET_VNET_HDR, &one, sizeof(one)) < 0) {
		fprintf(stderr, "[-] PACKET_VNET_HDR: %s\n", strerror(errno));
		close(pf);
		return -1;
	}

	buf = malloc(sizeof(vh) + len);
	if (!buf) {
		close(pf);
		return -1;
	}

	memset(&vh, 0, sizeof(vh));
	memcpy(buf, &vh, sizeof(vh));

	memset(buf + sizeof(vh), 0xff, ETH_ALEN);
	memset(buf + sizeof(vh) + ETH_ALEN, 0x02, ETH_ALEN);
	buf[sizeof(vh) + 12] = 0x08;
	buf[sizeof(vh) + 13] = 0x00;
	memset(buf + sizeof(vh) + 14, 0x41, len - 14);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex = idx;
	sll.sll_halen = ETH_ALEN;
	memset(sll.sll_addr, 0xff, ETH_ALEN);

	r = sendto(pf, buf, sizeof(vh) + len, 0,
		   (struct sockaddr *)&sll, sizeof(sll));
	if (r < 0)
		fprintf(stderr, "[-] sendto(len=%d): %s\n", len, strerror(errno));
	else
		fprintf(stderr, "[+] sendto(len=%d) -> %zd\n", len, (size_t)r);

	free(buf);
	close(pf);
	return r < 0 ? -1 : 0;
}

int main(void)
{
	const char *user_port = "lan1";
	const char *conduit = "eth0";
	int s, idx, mtu, i;
	int sizes[] = { 8000, 6000, 4200, 4100, 4064, 5000, 8968 };

	setvbuf(stderr, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return 1;
	}

	dump_ifaces();

	if (if_get_index(s, user_port) < 0) {
		fprintf(stderr, "[-] no DSA user port '%s' — dsa_loop did not probe\n",
			user_port);
		return 1;
	}

	if_up(s, conduit);
	if (if_up(s, user_port) < 0)
		return 1;

	idx = if_get_index(s, user_port);
	fprintf(stderr, "[+] %s ifindex=%d mtu=%d (conduit %s mtu=%d)\n",
		user_port, idx, if_get_mtu(s, user_port),
		conduit, if_get_mtu(s, conduit));

	if (if_set_mtu(s, user_port, BIG_MTU) < 0) {
		fprintf(stderr, "[-] could not raise MTU, paged skb unreachable "
				"via AF_PACKET\n");
		return 1;
	}
	mtu = if_get_mtu(s, user_port);
	fprintf(stderr, "[+] %s mtu now %d (conduit %s mtu=%d)\n",
		user_port, mtu, conduit, if_get_mtu(s, conduit));

	cat_file("/sys/class/net/eth0/dsa/tagging");
	dump_sg(s, user_port);
	dump_sg(s, conduit);
	dump_iface_stats(user_port);

	for (i = 0; i < (int)(sizeof(sizes) / sizeof(sizes[0])); i++) {
		if (sizes[i] > mtu)
			continue;
		fprintf(stderr, "[*] round %d: len=%d\n", i, sizes[i]);
		send_paged_frame(idx, sizes[i]);
		usleep(50000);
		dump_iface_stats(user_port);
	}

	fprintf(stderr, "[*] done — no crash?\n");
	return 0;
}
