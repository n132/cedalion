// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

static int smbus_xfer(int fd, char rw, uint8_t cmd, int size,
		      union i2c_smbus_data *data)
{
	struct i2c_smbus_ioctl_data args;

	memset(&args, 0, sizeof(args));
	args.read_write = rw;
	args.command = cmd;
	args.size = size;
	args.data = data;
	return ioctl(fd, I2C_SMBUS, &args);
}

struct stage_cfg {
	const char *name;
	int timeout;
	int threads;
	int iters;
	int churn;
	uint8_t addr_base;
	uint8_t addr_count;
};

struct worker_arg {
	const struct stage_cfg *cfg;
	int id;
};

static void set_affinity_best_effort(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

static void churn_syscalls(int fd, int count)
{
	unsigned long funcs;
	struct timespec ts;
	int i;

	for (i = 0; i < count; i++) {
		ioctl(fd, I2C_FUNCS, &funcs);
		clock_gettime(CLOCK_MONOTONIC, &ts);
		syscall(SYS_getpid);
		sched_yield();
	}
}

static void *worker_thread(void *opaque)
{
	const struct worker_arg *arg = opaque;
	const struct stage_cfg *cfg = arg->cfg;
	int fd;
	int i;
	int ok = 0;
	int timeouts = 0;
	int other = 0;

	set_affinity_best_effort(arg->id & 1);

	fd = open("/dev/i2c-0", O_RDWR);
	if (fd < 0) {
		perror("open");
		return NULL;
	}

	close(fd);

	fd = open("/dev/i2c-0", O_RDWR);
	if (fd < 0) {
		perror("open");
		return NULL;
	}

	for (i = 0; i < cfg->iters; i++) {
		union i2c_smbus_data data;
		uint8_t addr = cfg->addr_base + ((i + arg->id) % cfg->addr_count);
		int ret;
		int saved_errno;

		if (ioctl(fd, I2C_SLAVE_FORCE, addr) < 0) {
			perror("I2C_SLAVE_FORCE");
			break;
		}
		if (ioctl(fd, I2C_TIMEOUT, cfg->timeout) < 0) {
			perror("I2C_TIMEOUT");
			break;
		}

		memset(&data, 0, sizeof(data));
		data.block[0] = 32;
		ret = smbus_xfer(fd, I2C_SMBUS_READ, (uint8_t)i,
				 I2C_SMBUS_I2C_BLOCK_DATA, &data);
		saved_errno = errno;
		churn_syscalls(fd, cfg->churn);

		if (ret == 0) {
			ok++;
		} else if (saved_errno == ETIMEDOUT) {
			timeouts++;
		} else {
			other++;
			if (other < 8) {
				printf("[%s:t%d] iter=%d addr=0x%02x ret=%d errno=%d (%s)\n",
				       cfg->name, arg->id, i, addr, ret,
				       saved_errno, strerror(saved_errno));
			}
		}

		if ((i % 10000) == 0) {
			printf("[%s:t%d] iter=%d ok=%d timeouts=%d other=%d\n",
			       cfg->name, arg->id, i, ok, timeouts, other);
		}
	}

	printf("[%s:t%d] done ok=%d timeouts=%d other=%d\n",
	       cfg->name, arg->id, ok, timeouts, other);
	close(fd);
	return NULL;
}

static void run_stage(const struct stage_cfg *cfg)
{
	pthread_t tids[4];
	struct worker_arg args[4];
	int i;

	printf("=== stage %s timeout=%d threads=%d iters=%d churn=%d ===\n",
	       cfg->name, cfg->timeout, cfg->threads, cfg->iters, cfg->churn);

	for (i = 0; i < cfg->threads; i++) {
		memset(&args[i], 0, sizeof(args[i]));
		args[i].cfg = cfg;
		args[i].id = i;
		pthread_create(&tids[i], NULL, worker_thread, &args[i]);
	}

	for (i = 0; i < cfg->threads; i++)
		pthread_join(tids[i], NULL);
}

int main(int argc, char **argv)
{
	struct stage_cfg cfg = {
		.name = "default",
		.timeout = 1,
		.threads = 1,
		.iters = 1000,
		.churn = 0,
		.addr_base = 0x50,
		.addr_count = 8,
	};

	if (argc > 1)
		cfg.timeout = atoi(argv[1]);
	if (argc > 2)
		cfg.threads = atoi(argv[2]);
	if (argc > 3)
		cfg.iters = atoi(argv[3]);
	if (argc > 4)
		cfg.churn = atoi(argv[4]);

	if (cfg.threads < 1)
		cfg.threads = 1;
	if (cfg.threads > 4)
		cfg.threads = 4;
	if (cfg.iters < 1)
		cfg.iters = 1;
	if (cfg.churn < 0)
		cfg.churn = 0;

	run_stage(&cfg);

	return 0;
}
