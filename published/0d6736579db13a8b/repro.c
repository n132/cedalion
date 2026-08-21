// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>

#define AF_TIPC_                30

#define TIPC_NL_BEARER_DISABLE  2
#define TIPC_NL_BEARER_ENABLE   3
#define TIPC_NL_NET_SET         15

#define TIPC_NLA_BEARER         1
#define TIPC_NLA_NET            7
#define TIPC_NLA_BEARER_NAME    1
#define TIPC_NLA_NET_ID         1
#define TIPC_NLA_NET_NODEID     3
#define TIPC_NLA_NET_NODEID_W1  4

#define TIPC_CLUSTER_SCOPE_     2
#define TIPC_ADDR_NAMESEQ_      1
#define TIPC_NET_ID_VAL         4711

#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER          1
#endif
#ifndef IFLA_NET_NS_FD
#define IFLA_NET_NS_FD          28
#endif

struct tipc_service_range_ { unsigned int type, lower, upper; };
struct sockaddr_tipc_ {
	unsigned short family;
	unsigned char  addrtype;
	signed   char  scope;
	union { unsigned char pad[12]; struct tipc_service_range_ nameseq; } addr;
};

static int die(const char *m){ perror(m); _exit(1); return 0; }

static void nl_add_attr(struct nlmsghdr *nlh, int type, const void *data, int len)
{
	struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	int alen = NLA_HDRLEN + len;
	a->nla_type = type;
	a->nla_len = alen;
	if (len) memcpy((char *)a + NLA_HDRLEN, data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(alen);
}
static struct nlattr *nl_nest_start(struct nlmsghdr *nlh, int type)
{
	struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	a->nla_type = type | NLA_F_NESTED;
	a->nla_len = NLA_HDRLEN;
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_HDRLEN;
	return a;
}
static void nl_nest_end(struct nlmsghdr *nlh, struct nlattr *a)
{
	a->nla_len = (char *)nlh + nlh->nlmsg_len - (char *)a;
}
static int nl_open(int proto)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, proto);
	if (fd < 0) die("socket netlink");
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) die("bind netlink");
	return fd;
}
static int nl_send(int fd, struct nlmsghdr *nlh)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_seq = 1;
	return sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
}
static int nl_recv_ack(int fd)
{
	char buf[8192];
	int n = recv(fd, buf, sizeof(buf), 0);
	if (n < 0) return -errno;
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nlh);
		return e->error;
	}
	return 0;
}

static int resolve_tipc_family(int fd)
{
	char buf[2048];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	gh->cmd = CTRL_CMD_GETFAMILY;
	gh->version = 1;
	const char *name = "TIPCv2";
	nl_add_attr(nlh, CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);
	if (nl_send(fd, nlh) < 0) die("send getfamily");
	int n = recv(fd, buf, sizeof(buf), 0);
	if (n < 0) die("recv getfamily");
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) return -1;
	struct nlattr *a = (struct nlattr *)((char *)NLMSG_DATA(nlh) + GENL_HDRLEN);
	int rem = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	while (rem > 0) {
		if (a->nla_type == CTRL_ATTR_FAMILY_ID)
			return *(unsigned short *)((char *)a + NLA_HDRLEN);
		rem -= NLA_ALIGN(a->nla_len);
		a = (struct nlattr *)((char *)a + NLA_ALIGN(a->nla_len));
	}
	return -1;
}

static int tipc_net_set(int fd, int fam, unsigned int net_id, const unsigned char id[16])
{
	char buf[1024];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = fam;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	gh->cmd = TIPC_NL_NET_SET;
	gh->version = 1;
	struct nlattr *net = nl_nest_start(nlh, TIPC_NLA_NET);
	nl_add_attr(nlh, TIPC_NLA_NET_ID, &net_id, sizeof(net_id));
	unsigned long long lo, hi;
	memcpy(&lo, id, 8); memcpy(&hi, id + 8, 8);
	nl_add_attr(nlh, TIPC_NLA_NET_NODEID, &lo, sizeof(lo));
	nl_add_attr(nlh, TIPC_NLA_NET_NODEID_W1, &hi, sizeof(hi));
	nl_nest_end(nlh, net);
	if (nl_send(fd, nlh) < 0) die("send net_set");
	return nl_recv_ack(fd);
}

static int tipc_bearer_cmd(int fd, int fam, int cmd, const char *bname)
{
	char buf[1024];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = fam;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	gh->cmd = cmd;
	gh->version = 1;
	struct nlattr *b = nl_nest_start(nlh, TIPC_NLA_BEARER);
	nl_add_attr(nlh, TIPC_NLA_BEARER_NAME, bname, strlen(bname) + 1);
	nl_nest_end(nlh, b);
	if (nl_send(fd, nlh) < 0) die("send bearer cmd");
	return nl_recv_ack(fd);
}

static void create_veth(int rt, const char *name, const char *peer, int peer_nsfd)
{
	char buf[2048];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nl_add_attr(nlh, IFLA_IFNAME, name, strlen(name) + 1);
	struct nlattr *linfo = nl_nest_start(nlh, IFLA_LINKINFO);
	nl_add_attr(nlh, IFLA_INFO_KIND, "veth", 5);
	struct nlattr *idata = nl_nest_start(nlh, IFLA_INFO_DATA);
	struct nlattr *vpeer = nl_nest_start(nlh, VETH_INFO_PEER);
	struct ifinfomsg *pifi = (struct ifinfomsg *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	memset(pifi, 0, sizeof(*pifi));
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + sizeof(struct ifinfomsg);
	nl_add_attr(nlh, IFLA_IFNAME, peer, strlen(peer) + 1);
	if (peer_nsfd >= 0)
		nl_add_attr(nlh, IFLA_NET_NS_FD, &peer_nsfd, sizeof(peer_nsfd));
	nl_nest_end(nlh, vpeer);
	nl_nest_end(nlh, idata);
	nl_nest_end(nlh, linfo);
	if (nl_send(rt, nlh) < 0) die("send newlink veth");
	int e = nl_recv_ack(rt);
	if (e) { errno = -e; perror("veth create"); }
}
static void if_up(const char *name)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { perror("socket ifup"); return; }
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) perror("SIOCGIFFLAGS");
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) perror("SIOCSIFFLAGS");
	close(s);
}

static void write_str(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) return;
	write(fd, val, strlen(val));
	close(fd);
}
static void failslab_arm(int prob)
{
	char p[16];
	snprintf(p, sizeof(p), "%d", prob);
	write_str("/sys/kernel/debug/failslab/probability", p);
	write_str("/sys/kernel/debug/failslab/interval", "1");
	write_str("/sys/kernel/debug/failslab/times", "-1");
	write_str("/sys/kernel/debug/failslab/space", "0");
	write_str("/sys/kernel/debug/failslab/verbose", "0");
	write_str("/sys/kernel/debug/failslab/task-filter", "0");
	write_str("/sys/kernel/debug/failslab/ignore-gfp-wait", "1");
}
static void failslab_disarm(void)
{
	write_str("/sys/kernel/debug/failslab/probability", "0");
	write_str("/sys/kernel/debug/failslab/times", "0");
}

static int gfd = -1, fam = -1;

static int setup_tipc_ns(unsigned int net_id, const unsigned char nodeid[16],
			 const char *ifname, int do_publish)
{
	gfd = nl_open(NETLINK_GENERIC);
	fam = resolve_tipc_family(gfd);
	if (fam < 0) { fprintf(stderr, "no TIPCv2 family\n"); return -1; }
	int e = tipc_net_set(gfd, fam, net_id, nodeid);
	if (e) fprintf(stderr, "net_set: %s\n", strerror(-e));
	if_up(ifname);
	char bname[64];
	snprintf(bname, sizeof(bname), "eth:%s", ifname);
	e = tipc_bearer_cmd(gfd, fam, TIPC_NL_BEARER_ENABLE, bname);
	if (e) fprintf(stderr, "enable bearer %s: %s\n", bname, strerror(-e));
	else   fprintf(stderr, "[*] bearer %s enabled\n", bname);

	if (do_publish) {

		for (int i = 0; i < 4; i++) {
			int s = socket(AF_TIPC_, SOCK_RDM, 0);
			if (s < 0) { perror("socket AF_TIPC"); return -1; }
			struct sockaddr_tipc_ sa;
			memset(&sa, 0, sizeof(sa));
			sa.family = AF_TIPC_;
			sa.addrtype = TIPC_ADDR_NAMESEQ_;
			sa.scope = TIPC_CLUSTER_SCOPE_;
			sa.addr.nameseq.type = 0x1234 + i;
			sa.addr.nameseq.lower = 100;
			sa.addr.nameseq.upper = 100;
			if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0)
				perror("bind tipc publication");
		}
		fprintf(stderr, "[*] cluster-scope publications bound\n");
	}
	return 0;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	mkdir("/sys/kernel/debug", 0755);
	mount("none", "/sys/kernel/debug", "debugfs", 0, NULL);

	static const unsigned char NID_P[16] = {
		0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,
		0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11 };
	static const unsigned char NID_C[16] = {
		0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,
		0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22 };

	int sync_pipe[2], go_pipe[2];
	if (pipe(sync_pipe) < 0) die("pipe");
	if (pipe(go_pipe) < 0) die("pipe");

	pid_t child = fork();
	if (child < 0) die("fork");
	if (child == 0) {
		close(sync_pipe[0]); close(go_pipe[1]);
		if (unshare(CLONE_NEWNET) < 0) die("child unshare netns");
		char c = 1;
		write(sync_pipe[1], &c, 1);
		read(go_pipe[0], &c, 1);
		if_up("lo");
		setup_tipc_ns(TIPC_NET_ID_VAL, NID_C, "veth1", 0);
		for (;;) pause();
		_exit(0);
	}

	close(sync_pipe[1]); close(go_pipe[0]);
	char c;
	read(sync_pipe[0], &c, 1);

	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/ns/net", child);
	int peer_nsfd = open(path, O_RDONLY);
	if (peer_nsfd < 0) die("open child netns");

	int rt = nl_open(NETLINK_ROUTE);
	create_veth(rt, "veth0", "veth1", peer_nsfd);
	close(rt);

	write(go_pipe[1], &c, 1);
	usleep(300 * 1000);

	setup_tipc_ns(TIPC_NET_ID_VAL, NID_P, "veth0", 1);

	fprintf(stderr, "[*] both sides up; phase1: let link establish (peer_net)...\n");
	sleep(4);

	fprintf(stderr, "[*] phase2: failslab + link reset cycles\n");
	for (int round = 0; round < 120; round++) {
		failslab_disarm();
		tipc_bearer_cmd(gfd, fam, TIPC_NL_BEARER_DISABLE, "eth:veth0");
		usleep(150 * 1000);

		failslab_arm(15);
		tipc_bearer_cmd(gfd, fam, TIPC_NL_BEARER_ENABLE, "eth:veth0");

		usleep(1500 * 1000);
	}

	failslab_disarm();
	fprintf(stderr, "[*] done (no crash observed)\n");
	kill(child, SIGKILL);
	return 0;
}
