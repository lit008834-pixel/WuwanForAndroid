// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "program.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }
static int fail(const char *stage) {
    fprintf(stderr, "eBPF %s: errno=%d (%s)\n", stage, errno, strerror(errno));
    return -1;
}

static int load_program(unsigned uid, unsigned tun) {
    struct bpf_insn instructions[64];
    char verifier[16384] = {0};
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    attr.expected_attach_type = WUWAN_TCX_EGRESS;
    attr.insn_cnt = (unsigned)wuwan_program(instructions, uid, tun);
    attr.insns = (uintptr_t)instructions;
    attr.license = (uintptr_t)"GPL";
    attr.log_buf = (uintptr_t)verifier;
    attr.log_size = sizeof(verifier);
    attr.log_level = 1;
    memcpy(attr.prog_name, "wuwan_egress", sizeof("wuwan_egress"));
    int fd = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        fail("BPF_PROG_LOAD");
        fprintf(stderr, "%.16000s\n", verifier);
    }
    return fd;
}

static int attach(int program, unsigned index) {
    // First 16 bytes of bpf_attr.link_create; all optional fields are zero.
    struct { uint32_t program, target, type, flags; } attr = {
        (uint32_t)program, index, WUWAN_TCX_EGRESS, 0
    };
    int fd = (int)syscall(__NR_bpf, WUWAN_LINK_CREATE, &attr, sizeof(attr));
    if (fd < 0) fail("BPF_LINK_CREATE/TCX_EGRESS");
    return fd;
}

static int open_tun(unsigned mtu, unsigned *index) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) fd = open("/dev/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) return fail("open TUN");
    struct ifreq request = {0};
    strcpy(request.ifr_name, "wuwan%d");
    request.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &request) < 0) goto error;
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) goto error;
    request.ifr_mtu = (int)mtu;
    if (ioctl(sock, SIOCSIFMTU, &request) < 0) { close(sock); goto error; }
    request.ifr_flags = IFF_UP | IFF_POINTOPOINT;
    if (ioctl(sock, SIOCSIFFLAGS, &request) < 0) { close(sock); goto error; }
    close(sock);
    *index = if_nametoindex(request.ifr_name);
    if (!*index) goto error;
    return fd;
error:
    fail("configure TUN");
    close(fd);
    return -1;
}

struct link { unsigned index; int fd; };
static struct link links[256];
static size_t link_count;
static void detach_all(void) {
    while (link_count) close(links[--link_count].fd);
}

// Attach to down interfaces too: activating a pre-existing cellular/Wi-Fi
// interface must not create a polling gap. RTM_NEWLINK handles new interfaces.
static int sync_links(int program, unsigned tun) {
    struct if_nameindex *interfaces = if_nameindex();
    if (!interfaces) return fail("enumerate interfaces");
    for (size_t i = 0; i < link_count;) {
        int found = 0;
        for (struct if_nameindex *p = interfaces; p->if_index; ++p)
            if (p->if_index == links[i].index) found = 1;
        if (!found) {
            close(links[i].fd);
            links[i] = links[--link_count];
        } else ++i;
    }
    int result = 0;
    for (struct if_nameindex *p = interfaces; p->if_index; ++p) {
        if (p->if_index == tun || !strcmp(p->if_name, "lo")) continue;
        int found = 0;
        for (size_t i = 0; i < link_count; ++i)
            if (links[i].index == p->if_index) found = 1;
        if (found) continue;
        if (link_count == sizeof(links)/sizeof(links[0])) {
            errno = E2BIG; result = fail("too many interfaces"); break;
        }
        int fd = attach(program, p->if_index);
        if (fd < 0) { result = -1; break; }
        links[link_count++] = (struct link){p->if_index, fd};
    }
    if_freenameindex(interfaces);
    return result;
}

static int send_tun(int socket_fd, int tun) {
    char byte = 'T';
    struct iovec io = {&byte, 1};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg = {0};
    msg.msg_iov = &io; msg.msg_iovlen = 1;
    msg.msg_control = control.bytes; msg.msg_controllen = sizeof(control.bytes);
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &tun, sizeof(tun));
    return sendmsg(socket_fd, &msg, MSG_NOSIGNAL) == 1 ? 0 : fail("send TUN fd");
}

static int number(const char *text, unsigned min, unsigned max, unsigned *out) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || !*text || *end || value < min || value > max) return -1;
    *out = (unsigned)value;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 5) return 64;
    int probe = argc == 2 && !strcmp(argv[1], "probe");
    if (!probe && (argc != 5 || strcmp(argv[1], "serve"))) return 64;
    if (geteuid() != 0) { fprintf(stderr, "ROOT_DENIED\n"); return 77; }
    fprintf(stderr, "ROOT_GRANTED\n");
    unsigned uid = 0, mtu = 1500, tun_index = 0;
    if (!probe && (number(argv[3], 10000, 2147483647, &uid) ||
                   number(argv[4], 1280, 65535, &mtu))) return 64;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, stop); signal(SIGINT, stop); signal(SIGHUP, stop);
    struct rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
    (void)setrlimit(RLIMIT_MEMLOCK, &limit);
    int tun = -1, program = -1, server = -1, client = -1, events = -1, status = 1;
    tun = open_tun(mtu, &tun_index);
    if (tun < 0) goto cleanup;
    program = load_program(uid, tun_index);
    if (program < 0) goto cleanup;
    if (probe) {
        int link = attach(program, tun_index);
        if (link < 0) goto cleanup;
        close(link);
        puts("BPF_READY"); status = 0; goto cleanup;
    }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t name_len = strlen(argv[2]);
    if (!name_len || name_len > sizeof(address.sun_path)-2) goto cleanup;
    memcpy(address.sun_path+1, argv[2], name_len);
    server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0 || bind(server, (struct sockaddr *)&address,
        (socklen_t)(offsetof(struct sockaddr_un, sun_path)+1+name_len)) || listen(server, 1)) {
        fail("control socket"); goto cleanup;
    }
    struct pollfd waiting = {server, POLLIN, 0};
    if (poll(&waiting, 1, 15000) <= 0 || stopping) goto cleanup;
    client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0) goto cleanup;
    struct ucred credentials;
    socklen_t credentials_len = sizeof(credentials);
    if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_len) ||
        credentials.uid != uid) { errno = EACCES; fail("peer UID"); goto cleanup; }
    close(server); server = -1;
    events = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    struct sockaddr_nl netlink = {.nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK};
    if (events < 0 || bind(events, (struct sockaddr *)&netlink, sizeof(netlink))) {
        fail("interface monitor"); goto cleanup;
    }
    // Give the app the TUN first. No traffic is diverted until it explicitly
    // sends A after sing-box has finished starting all inbounds and outbounds.
    if (send_tun(client, tun)) goto cleanup;
    struct pollfd fds[2] = {{client, POLLIN, 0}, {events, POLLIN, 0}};
    int active = 0;
    while (!stopping) {
        int ready = poll(fds, 2, 15000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) break; // dead app / stalled heartbeat: release BPF links
        if (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        if (fds[0].revents & POLLIN) {
            char command;
            if (read(client, &command, 1) != 1 || command == 'Q') break;
            if (command == 'A' && !active) {
                if (sync_links(program, tun_index)) break;
                active = 1;
            } else if (command != 'H' || !active) break;
            if (send(client, "K", 1, MSG_NOSIGNAL) != 1) break;
        }
        if (fds[1].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        if (fds[1].revents & POLLIN) {
            char buffer[65536];
            if (recv(events, buffer, sizeof(buffer), 0) < 0) break;
            if (active && sync_links(program, tun_index)) break;
        }
    }
    status = 0;
cleanup:
    // Links go first; socket EOF tells Java rollback is complete. No pins,
    // iptables rules, routing rules or shared qdisc changes survive the helper.
    detach_all();
    if (program >= 0) close(program);
    if (tun >= 0) close(tun);
    if (events >= 0) close(events);
    if (server >= 0) close(server);
    if (client >= 0) close(client);
    return status;
}
