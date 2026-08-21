// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdint.h>

struct drm_mode_get_connector {
	uint64_t encoders_ptr;
	uint64_t modes_ptr;
	uint64_t props_ptr;
	uint64_t prop_values_ptr;
	uint32_t count_modes;
	uint32_t count_props;
	uint32_t count_encoders;
	uint32_t encoder_id;
	uint32_t connector_id;
	uint32_t connector_type;
	uint32_t connector_type_id;
	uint32_t connection;
	uint32_t mm_width;
	uint32_t mm_height;
	uint32_t subpixel;
	uint32_t pad;
};

struct drm_mode_card_res {
	uint64_t fb_id_ptr;
	uint64_t crtc_id_ptr;
	uint64_t connector_id_ptr;
	uint64_t encoder_id_ptr;
	uint32_t count_fbs;
	uint32_t count_crtcs;
	uint32_t count_connectors;
	uint32_t count_encoders;
	uint32_t min_width, max_width;
	uint32_t min_height, max_height;
};

#define DRM_IOCTL_BASE 'd'
#define DRM_IOWR(nr,type) _IOWR(DRM_IOCTL_BASE,nr,type)
#define DRM_IOCTL_MODE_GETRESOURCES  DRM_IOWR(0xA0, struct drm_mode_card_res)
#define DRM_IOCTL_MODE_GETCONNECTOR  DRM_IOWR(0xA7, struct drm_mode_get_connector)
#define DRM_IOCTL_SET_MASTER         _IO(DRM_IOCTL_BASE, 0x1e)

static uint8_t edid[128];

static void build_edid(void)
{
	memset(edid, 0, sizeof(edid));

	edid[0] = 0x00;
	edid[1] = 0xFF; edid[2] = 0xFF; edid[3] = 0xFF;
	edid[4] = 0xFF; edid[5] = 0xFF; edid[6] = 0xFF;
	edid[7] = 0x00;

	edid[8]  = 0x10; edid[9]  = 0xAC;
	edid[10] = 0x01; edid[11] = 0x00;

	edid[18] = 1;
	edid[19] = 3;

	edid[20] = 0x80;
	edid[21] = 0x20;
	edid[22] = 0x18;
	edid[23] = 0x78;

	edid[24] = 0x01;

	int d0 = 54;
	edid[d0 + 0] = 0x00;
	edid[d0 + 1] = 0x00;
	edid[d0 + 2] = 0x00;
	edid[d0 + 3] = 0xFD;
	edid[d0 + 4] = 0x00;
	edid[d0 + 5] = 50;
	edid[d0 + 6] = 75;
	edid[d0 + 7] = 30;
	edid[d0 + 8] = 90;
	edid[d0 + 9] = 20;
	edid[d0 + 10] = 0x02;
	edid[d0 + 11] = 0x00;
	edid[d0 + 12] = 0x00;
	edid[d0 + 13] = 0x00;
	edid[d0 + 14] = 0x00;
	edid[d0 + 15] = 0x00;
	edid[d0 + 16] = 0x00;
	edid[d0 + 17] = 200;

	int d;
	for (d = 1; d < 4; d++) {
		int off = 54 + d * 18;
		edid[off + 0] = 0x00;
		edid[off + 1] = 0x00;
		edid[off + 2] = 0x00;
		edid[off + 3] = 0x10;
		edid[off + 4] = 0x00;
	}

	edid[126] = 0;

	unsigned int sum = 0;
	int i;
	for (i = 0; i < 127; i++)
		sum += edid[i];
	edid[127] = (uint8_t)((256 - (sum & 0xff)) & 0xff);
}

static int push_override_for_minor(const char *minor_path)
{
	DIR *d = opendir(minor_path);
	if (!d)
		return 0;
	struct dirent *e;
	int wrote = 0;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		char p[512];
		snprintf(p, sizeof(p), "%s/%s/edid_override", minor_path, e->d_name);
		int fd = open(p, O_WRONLY);
		if (fd < 0)
			continue;
		ssize_t w = write(fd, edid, sizeof(edid));
		if (w == (ssize_t)sizeof(edid)) {
			printf("[+] wrote EDID override to %s\n", p);
			wrote++;
		} else {
			printf("[-] write to %s failed: %zd (%s)\n", p, w, strerror(errno));
		}
		close(fd);
	}
	closedir(d);
	return wrote;
}

static void push_all_overrides(void)
{
	const char *base = "/sys/kernel/debug/dri";
	DIR *d = opendir(base);
	if (!d) {
		printf("[-] cannot open %s: %s\n", base, strerror(errno));
		return;
	}
	struct dirent *e;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		char p[512];
		snprintf(p, sizeof(p), "%s/%s", base, e->d_name);
		push_override_for_minor(p);
	}
	closedir(d);
}

static void reprobe_card(const char *dev)
{
	int fd = open(dev, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		printf("[-] open %s: %s\n", dev, strerror(errno));
		return;
	}

	ioctl(fd, DRM_IOCTL_SET_MASTER, 0);

	struct drm_mode_card_res res;
	memset(&res, 0, sizeof(res));
	if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) {
		printf("[-] GETRESOURCES %s: %s\n", dev, strerror(errno));
		close(fd);
		return;
	}
	uint32_t n = res.count_connectors;
	printf("[*] %s: %u connectors\n", dev, n);
	if (!n) { close(fd); return; }

	uint32_t *conns = calloc(n, sizeof(uint32_t));
	memset(&res, 0, sizeof(res));
	res.connector_id_ptr = (uint64_t)(uintptr_t)conns;
	res.count_connectors = n;
	if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) {
		printf("[-] GETRESOURCES(2) %s: %s\n", dev, strerror(errno));
		free(conns); close(fd); return;
	}

	for (uint32_t i = 0; i < res.count_connectors; i++) {
		struct drm_mode_get_connector gc;
		memset(&gc, 0, sizeof(gc));
		gc.connector_id = conns[i];
		gc.count_modes = 0;
		printf("[*] forcing reprobe of connector %u ...\n", conns[i]);
		fflush(stdout);
		ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, &gc);
		printf("[*] connector %u reprobe returned\n", conns[i]);
	}
	free(conns);
	close(fd);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	mkdir("/sys/kernel/debug", 0755);
	if (mount("none", "/sys/kernel/debug", "debugfs", 0, NULL) != 0 && errno != EBUSY)
		printf("[-] mount debugfs: %s\n", strerror(errno));
	else
		printf("[+] debugfs mounted\n");

	build_edid();
	printf("[*] EDID checksum byte = 0x%02x\n", edid[127]);

	push_all_overrides();

	char dev[64];
	for (int i = 0; i < 16; i++) {
		snprintf(dev, sizeof(dev), "/dev/dri/card%d", i);
		if (access(dev, F_OK) == 0)
			reprobe_card(dev);
	}

	printf("[*] done (if we got here, the divide-by-zero did not fire)\n");
	return 0;
}
