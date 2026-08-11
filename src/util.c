/* Copyright (c) 2025 Sergio Randriamihoatra.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int parse_int(const char *s, int min, int max, const char *what)
{
    char *end;
    long  v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < min || v > max) {
        fprintf(stderr, "invalid %s: %s\n", what, s);
        return -1;
    }
    return (int)v;
}

const char *addr_to_str(const struct sockaddr_storage *ss, char *buf,
                        size_t buflen)
{
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *sa = (const struct sockaddr_in *)ss;
        return inet_ntop(AF_INET, &sa->sin_addr, buf, buflen);
    }
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)ss;
        return inet_ntop(AF_INET6, &sa->sin6_addr, buf, buflen);
    }
    snprintf(buf, buflen, "?");
    return buf;
}

bool host_has_suffix(const char *host, const char *suffix)
{
    size_t hl = strlen(host), sl = strlen(suffix);
    return hl >= sl && strcasecmp(host + hl - sl, suffix) == 0;
}

bool is_onion(const char *host) { return host_has_suffix(host, ".onion"); }
bool is_i2p(const char *host)   { return host_has_suffix(host, ".i2p"); }

/* True if CAP_NET_RAW is in the process effective set (e.g. via
 * `setcap cap_net_raw+ep` or a privileged launcher) — checked through the
 * raw syscall so no libcap dependency is needed. */
bool have_cap_net_raw(void)
{
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid     = 0,
    };
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

    if (syscall(SYS_capget, &hdr, data) < 0)
        return geteuid() == 0;
    return (data[CAP_TO_INDEX(CAP_NET_RAW)].effective & CAP_TO_MASK(CAP_NET_RAW)) != 0;
}

/* Source address the kernel would use to reach @dst (via a throwaway
 * connected UDP socket).  Used only by the IPv4 raw path to fill ip_src. */
bool get_source_ip4(const struct in_addr *dst, struct in_addr *out)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port   = htons(9),
        .sin_addr   = *dst,
    };
    socklen_t sl = sizeof sa;
    bool ok = connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0 &&
              getsockname(fd, (struct sockaddr *)&sa, &sl) == 0;
    close(fd);

    if (ok)
        *out = sa.sin_addr;
    return ok;
}

int tcp_connect_timeout(const struct sockaddr *sa, socklen_t salen,
                        int timeout_s)
{
    int fd = socket(sa->sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;

    int rc = connect(fd, sa, salen);
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (rc != 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr = poll(&pfd, 1, timeout_s * 1000);
        if (pr <= 0 || !(pfd.revents & POLLOUT)) {
            close(fd);
            return -1;
        }
        int err = 0;
        socklen_t el = sizeof err;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0) {
            close(fd);
            return -1;
        }
    }

    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0)
        fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    return fd;
}

ssize_t send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n = send(fd, p + done, len - done, 0);
        if (n <= 0)
            return -1;
        done += (size_t)n;
    }
    return (ssize_t)done;
}

ssize_t recv_exact(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n = recv(fd, p + done, len - done, 0);
        if (n <= 0)
            return -1;
        done += (size_t)n;
    }
    return (ssize_t)done;
}

void sleep_ms(int ms)
{
    if (ms <= 0)
        return;
    struct timespec ts = {
        .tv_sec  = ms / 1000,
        .tv_nsec = (long)(ms % 1000) * 1000000L,
    };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
}
