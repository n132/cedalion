// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>

#ifndef KZALLOC_RET_OFF
#define KZALLOC_RET_OFF 0x651
#endif

#define FI "/sys/kernel/debug/failslab/"

static void wfile(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0) {
		printf("[-] open(%s): %s\n", path, strerror(errno));
		return;
	}
	if (write(fd, val, strlen(val)) < 0)
		printf("[-] write(%s, %s): %s\n", path, val, strerror(errno));
	close(fd);
}

static long rfile_l(const char *path)
{
	char buf[64];
	int fd = open(path, O_RDONLY);
	int n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	return strtol(buf, NULL, 0);
}

static void dump_fi(void)
{
	static const char *names[] = {
		"probability", "interval", "times", "space", "verbose",
		"task-filter", "stacktrace-depth", "require-start",
		"require-end", "ignore-gfp-wait", "cache-filter", NULL
	};
	char path[128], buf[64];
	int i, fd, n;

	for (i = 0; names[i]; i++) {
		snprintf(path, sizeof(path), FI "%s", names[i]);
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			printf("[-] %-18s <missing: %s>\n", names[i],
			       strerror(errno));
			continue;
		}
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n < 0)
			n = 0;
		buf[n] = 0;
		while (n && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
			buf[--n] = 0;
		printf("[=] %-18s %s\n", names[i], buf);
	}
}

static unsigned long ksym(const char *name)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[512], sym[256];
	unsigned long addr, ret = 0;
	char type;

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx %c %255s", &addr, &type, sym) != 3)
			continue;
		if (!strcmp(sym, name)) {
			ret = addr;
			break;
		}
	}
	fclose(f);
	return ret;
}

struct usb_raw_init {
	uint8_t driver_name[128];
	uint8_t device_name[128];
	uint8_t speed;
};

#define USB_RAW_EVENT_CONNECT		1
#define USB_RAW_EVENT_CONTROL		2

struct usb_raw_event {
	uint32_t type;
	uint32_t length;
	uint8_t data[0];
};

struct usb_raw_ep_io {
	uint16_t ep;
	uint16_t flags;
	uint32_t length;
	uint8_t data[0];
};

#define USB_RAW_IOCTL_INIT	_IOW('U', 0, struct usb_raw_init)
#define USB_RAW_IOCTL_RUN	_IO('U', 1)
#define USB_RAW_IOCTL_EVENT_FETCH _IOR('U', 2, struct usb_raw_event)
#define USB_RAW_IOCTL_EP0_WRITE	_IOW('U', 3, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP0_READ	_IOWR('U', 4, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_CONFIGURE	_IO('U', 9)
#define USB_RAW_IOCTL_VBUS_DRAW	_IOW('U', 10, uint32_t)
#define USB_RAW_IOCTL_EP0_STALL	_IO('U', 12)

struct usb_ctrlrequest {
	uint8_t bRequestType;
	uint8_t bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
} __attribute__((packed));

struct ep0_io {
	uint16_t ep;
	uint16_t flags;
	uint32_t length;
	uint8_t data[4096];
};

static uint8_t dev_desc[18] = {
	0x12, 0x01,
	0x00, 0x02,
	0xff, 0xff, 0xff,
	0x40,
	0x04, 0x23,
	0x3f, 0x02,
	0x00, 0x01,
	0x00, 0x00, 0x00,
	0x01,
};

static uint8_t cfg_desc[25] = {

	0x09, 0x02, 25, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32,

	0x09, 0x04, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0x00,

	0x07, 0x05, 0x84, 0x01, 0x08, 0x00, 0x04,
};

static int rg_open(void)
{
	int fd = open("/dev/raw-gadget", O_RDWR);
	FILE *f;
	char line[256], name[64];
	int minor;

	if (fd >= 0)
		return fd;

	f = fopen("/proc/misc", "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			if (sscanf(line, "%d %63s", &minor, name) == 2 &&
			    !strcmp(name, "raw-gadget")) {
				unlink("./raw-gadget");
				if (mknod("./raw-gadget", S_IFCHR | 0600,
					  makedev(10, minor)) == 0) {
					fd = open("./raw-gadget", O_RDWR);
					break;
				}
			}
		}
		fclose(f);
	}
	return fd;
}

static void ep0_stall(int fd)
{
	if (ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0) < 0)
		printf("[-] ep0_stall: %s\n", strerror(errno));
}

static void ep0_reply(int fd, struct usb_ctrlrequest *c, struct ep0_io *io)
{
	int rv;

	io->ep = 0;
	io->flags = 0;
	if ((c->bRequestType & 0x80) && c->wLength)
		rv = ioctl(fd, USB_RAW_IOCTL_EP0_WRITE, io);
	else
		rv = ioctl(fd, USB_RAW_IOCTL_EP0_READ, io);
	if (rv < 0)
		printf("[-] ep0 reply (bRequestType %02x bRequest %02x len %u): %s\n",
		       c->bRequestType, c->bRequest, io->length, strerror(errno));
}

static void handle_control(int fd, struct usb_ctrlrequest *c)
{
	struct ep0_io io;
	unsigned int n;

	io.ep = 0;
	io.flags = 0;
	io.length = 0;
	memset(io.data, 0, 64);

	if (!(c->bRequestType & 0x80)) {
		switch (c->bRequestType & 0x60) {
		case 0x00:
			if (c->bRequest == 0x09) {
				if (ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, 50) < 0)
					printf("[-] vbus_draw: %s\n", strerror(errno));
				if (ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0) < 0)
					printf("[-] configure: %s\n", strerror(errno));
			} else if (c->bRequest != 0x0b &&
				   c->bRequest != 0x01 &&
				   c->bRequest != 0x03 &&
				   c->bRequest != 0x05) {
				ep0_stall(fd);
				return;
			}
			break;
		case 0x40:
			break;
		default:
			ep0_stall(fd);
			return;
		}
		io.length = c->wLength > sizeof(io.data) ?
				sizeof(io.data) : c->wLength;
		ep0_reply(fd, c, &io);
		return;
	}

	switch (c->bRequestType & 0x60) {
	case 0x00:
		switch (c->bRequest) {
		case 0x06:
			switch (c->wValue >> 8) {
			case 1:
				n = sizeof(dev_desc);
				if (n > c->wLength)
					n = c->wLength;
				memcpy(io.data, dev_desc, n);
				break;
			case 2:
				n = sizeof(cfg_desc);
				if (n > c->wLength)
					n = c->wLength;
				memcpy(io.data, cfg_desc, n);
				break;
			default:
				ep0_stall(fd);
				return;
			}
			io.length = n;
			ep0_reply(fd, c, &io);
			return;
		case 0x08:
			io.data[0] = 1;
			io.length = c->wLength > 1 ? 1 : c->wLength;
			ep0_reply(fd, c, &io);
			return;
		case 0x00:
			io.data[0] = 1;
			io.data[1] = 0;
			io.length = c->wLength > 2 ? 2 : c->wLength;
			ep0_reply(fd, c, &io);
			return;
		case 0x0a:
			io.data[0] = 0;
			io.length = c->wLength > 1 ? 1 : c->wLength;
			ep0_reply(fd, c, &io);
			return;
		default:
			ep0_stall(fd);
			return;
		}
	case 0x40:
		n = c->wLength;
		if (n > sizeof(io.data))
			n = sizeof(io.data);
		memset(io.data, 0, n);

		if (c->bRequest == 0x00 && c->wIndex == 0x0a && n >= 1)
			io.data[0] = 65;
		io.length = n;
		ep0_reply(fd, c, &io);
		return;
	default:
		ep0_stall(fd);
		return;
	}
}

static int gadget_run(int seconds)
{
	struct usb_raw_init init;
	int fd;
	union {
		struct usb_raw_event ev;
		char buf[sizeof(struct usb_raw_event) + 64];
	} u;

	fd = rg_open();
	if (fd < 0) {
		printf("[-] cannot open /dev/raw-gadget: %s\n", strerror(errno));
		return -1;
	}

	memset(&init, 0, sizeof(init));
	strcpy((char *)init.driver_name, "dummy_udc");
	strcpy((char *)init.device_name, "dummy_udc.0");
	init.speed = 3;
	if (ioctl(fd, USB_RAW_IOCTL_INIT, &init) < 0) {
		printf("[-] USB_RAW_IOCTL_INIT: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	if (ioctl(fd, USB_RAW_IOCTL_RUN, 0) < 0) {
		printf("[-] USB_RAW_IOCTL_RUN: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	printf("[+] fake em28xx DVB stick attached (2304:023f)\n");
	fflush(stdout);

	alarm(seconds);
	for (;;) {
		u.ev.type = 0;
		u.ev.length = 64;
		if (ioctl(fd, USB_RAW_IOCTL_EVENT_FETCH, &u.ev) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (u.ev.type == USB_RAW_EVENT_CONTROL)
			handle_control(fd, (struct usb_ctrlrequest *)u.ev.data);
	}
	close(fd);
	return 0;
}

static void arm_failslab(unsigned long start, unsigned long end,
			 const char *interval, const char *space,
			 const char *times)
{
	char buf[64];

	wfile(FI "ignore-gfp-wait", "N");
	wfile(FI "cache-filter", "N");
	wfile(FI "task-filter", "N");
	wfile(FI "probability", "100");
	wfile(FI "space", space);
	wfile(FI "verbose", "2");
	wfile(FI "stacktrace-depth", "32");

	snprintf(buf, sizeof(buf), "0x%lx", start);
	wfile(FI "require-start", buf);
	snprintf(buf, sizeof(buf), "0x%lx", end);
	wfile(FI "require-end", buf);
	wfile(FI "interval", interval);
	wfile(FI "times", times);
	dump_fi();
}

int main(void)
{
	unsigned long base, site;
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);

	wfile("/proc/sys/kernel/printk", "8 4 1 7\n");
	wfile("/proc/sys/kernel/kptr_restrict", "0");

	mkdir("/sys/kernel/debug", 0755);
	if (mount("none", "/sys/kernel/debug", "debugfs", 0, NULL) < 0 &&
	    errno != EBUSY)
		printf("[-] mount debugfs: %s\n", strerror(errno));

	base = ksym("em28xx_alloc_urbs");
	if (!base) {
		printf("[-] em28xx_alloc_urbs not found in /proc/kallsyms\n");
		return 1;
	}
	site = base + KZALLOC_RET_OFF;
	printf("[+] em28xx_alloc_urbs = %#lx, kzalloc call site = %#lx\n",
	       base, site);

	for (i = 0; i < 3; i++) {
		pid_t pid;

		printf("[*] attempt %d: fail kzalloc from i == 1 on\n", i);
		arm_failslab(site, site + 1, "1", "600", "100");

		pid = fork();
		if (pid == 0) {
			gadget_run(20);
			_exit(0);
		}
		waitpid(pid, NULL, 0);
		printf("[=] after attach: space %ld, times %ld\n",
		       rfile_l(FI "space"), rfile_l(FI "times"));
		sleep(2);
	}

	printf("[*] done\n");
	return 0;
}
