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

#include "ping.h"

#include "checksum.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Unified view of the ICMP / ICMPv6 echo header (identical layout). */
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t cksum;
    uint16_t id;
    uint16_t seq;
} echo_hdr;

typedef struct {
    int                     fd;
    bool                    raw;       /* raw socket vs unprivileged ICMP datagram */
    size_t                  rx_cap;
    struct sockaddr_storage dst;
    socklen_t               dst_len;
} ping_ctx;

static int open_ping_socket(int family, bool *raw)
{
    int proto = (family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6;

    if (have_cap_net_raw()) {
        int fd = socket(family, SOCK_RAW, proto);
        if (fd >= 0) {
            *raw = true;
            return fd;
        }
    }
    *raw = false;
    return socket(family, SOCK_DGRAM, proto);
}

/* Locate an echo-reply header inside a received buffer, if the packet is a
 * well-formed ICMP/ICMPv6 echo reply of the expected type. */
static const echo_hdr *parse_echo_reply(const char *rx, ssize_t r, bool raw,
                                        int family, uint8_t reply_type)
{
    const echo_hdr *rh = NULL;
    if (raw && family == AF_INET) {
        const struct ip *ip = (const struct ip *)rx;
        if (r >= (ssize_t)(sizeof(struct ip) + sizeof(echo_hdr))) {
            int hl = ip->ip_hl * 4;
            if (ip->ip_p == IPPROTO_ICMP && hl >= (int)sizeof(struct ip) &&
                r >= hl + (ssize_t)sizeof(echo_hdr))
                rh = (const echo_hdr *)(rx + hl);
        }
    } else if (r >= (ssize_t)sizeof(echo_hdr)) {
        rh = (const echo_hdr *)rx;
    }
    return (rh && rh->type == reply_type) ? rh : NULL;
}

static void record_rtt(int *replies, double *sum, double *min, double *max,
                       double rtt_ms)
{
    if (*replies == 0)
        *min = *max = rtt_ms;
    else {
        if (rtt_ms < *min) *min = rtt_ms;
        if (rtt_ms > *max) *max = rtt_ms;
    }
    *sum += rtt_ms;
    (*replies)++;
}

static void print_reply(ssize_t r, const struct sockaddr_storage *src,
                        unsigned seq, uint8_t type, double rtt_ms)
{
    char src_str[INET6_ADDRSTRLEN];
    addr_to_str(src, src_str, sizeof src_str);
    printf("Received %zd bytes  from=%s  seq=%u  type=%d  rtt=%.2f ms  (ECHO REPLY)\n",
           r, src_str, seq, type, rtt_ms);
}

int scan_address(int family, const struct sockaddr_storage *dst,
                 socklen_t dst_len, const ping_config *cfg)
{
    char dst_str[INET6_ADDRSTRLEN];
    addr_to_str(dst, dst_str, sizeof dst_str);

    bool raw;
    int  fd = open_ping_socket(family, &raw);
    if (fd < 0) {
        fprintf(stderr, "socket(%s, ICMP): %s\n",
                family == AF_INET ? "AF_INET" : "AF_INET6", strerror(errno));
        fprintf(stderr, "  enable unprivileged ICMP: "
                "sysctl -w net.ipv4.ping_group_range='0 2147483647'\n");
        return EXIT_FAILURE;
    }

    struct timeval tv = { .tv_sec = cfg->timeout_s, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    if (raw && family == AF_INET) {
        int one = 1;
        setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof one);
    }
    if (raw && family == AF_INET6) {
        int csum_off = 2; /* ICMPv6 checksum field offset; kernel fills it */
        setsockopt(fd, IPPROTO_IPV6, IPV6_CHECKSUM, &csum_off, sizeof csum_off);
        struct icmp6_filter f;
        ICMP6_FILTER_SETBLOCKALL(&f);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &f);
        setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &f, sizeof f);
    }

    uint16_t pid     = (uint16_t)(getpid() & 0xffff);
    size_t   icmp_len = sizeof(echo_hdr) + PING_DATA_SIZE; /* 8 + 32 */
    size_t   tx_off   = (family == AF_INET && raw) ? sizeof(struct ip) : 0;
    size_t   tx_len   = tx_off + icmp_len;

    char *tx = malloc(tx_len);
    if (!tx) {
        close(fd);
        return EXIT_FAILURE;
    }
    memset(tx, 0, tx_len);
    memset(tx + tx_off + sizeof(echo_hdr), 'A', PING_DATA_SIZE);

    echo_hdr *hdr = (echo_hdr *)(tx + tx_off);
    hdr->type     = (family == AF_INET) ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    hdr->code     = 0;
    hdr->id       = htons(pid);
    hdr->seq      = 0;

    if (family == AF_INET && raw) {
        struct ip *ip = (struct ip *)tx;
        ip->ip_v   = 4;
        ip->ip_hl  = 5;
        ip->ip_tos = 0;
        ip->ip_len = htons((uint16_t)tx_len);
        ip->ip_id  = htons(pid);
        ip->ip_off = 0;
        ip->ip_ttl = 64;
        ip->ip_p   = IPPROTO_ICMP;
        ip->ip_dst = ((const struct sockaddr_in *)dst)->sin_addr;
        ip->ip_src.s_addr = INADDR_ANY; /* kernel fills it if left 0.0.0.0 */
        struct in_addr src;
        if (get_source_ip4(&ip->ip_dst, &src))
            ip->ip_src = src;
        ip->ip_sum = checksum(ip, sizeof(struct ip)); /* static header */
    }

    ping_ctx ctx = {
        .fd     = fd,
        .raw    = raw,
        .rx_cap = PING_RX_CAP,
    };
    memcpy(&ctx.dst, dst, dst_len);
    ctx.dst_len = dst_len;

    printf("Pinging %s (%s) via %s\n", dst_str,
           family == AF_INET ? "IPv4" : "IPv6",
           raw ? "raw socket (CAP_NET_RAW)" : "unprivileged ICMP datagram socket");
    if (cfg->flood)
        printf("Flood mode: sending all %d probes back-to-back, no interval\n",
               cfg->count);

    uint8_t reply_type = (family == AF_INET) ? ICMP_ECHOREPLY : ICMP6_ECHO_REPLY;
    char   *rx         = malloc(ctx.rx_cap);
    if (!rx) {
        free(tx);
        close(fd);
        return EXIT_FAILURE;
    }

    int    sent = 0, replies = 0;
    double rtt_sum = 0, rtt_min = 0, rtt_max = 0;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (cfg->flood) {
        struct timespec *sent_ts   = malloc((size_t)cfg->count * sizeof *sent_ts);
        uint8_t         *answered  = calloc((size_t)cfg->count, 1);
        if (!sent_ts || !answered) {
            free(answered);
            free(sent_ts);
            free(rx);
            free(tx);
            close(fd);
            return EXIT_FAILURE;
        }

        /* Send the full payload back-to-back, recording each send time. */
        for (int i = 0; i < cfg->count; i++) {
            hdr->seq = htons((uint16_t)i);
            hdr->cksum = 0;
            if (raw && family == AF_INET)
                hdr->cksum = checksum(hdr, icmp_len);

            if (sendto(fd, tx, tx_len, 0, (struct sockaddr *)&ctx.dst,
                       ctx.dst_len) < 0) {
                fprintf(stderr, "sendto[%d]: %s\n", i, strerror(errno));
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &sent_ts[i]);
            sent++;
        }

        /* Collect replies until every probe is answered or the window
         * (per-probe timeout) elapses. */
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += cfg->timeout_s;

        while (replies < sent) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec &&
                 now.tv_nsec > deadline.tv_nsec)) {
                printf("Timeout – waiting for %d remaining replies\n",
                       sent - replies);
                break;
            }

            struct sockaddr_storage src;
            socklen_t sl = sizeof src;
            ssize_t r = recvfrom(fd, rx, ctx.rx_cap, 0,
                                 (struct sockaddr *)&src, &sl);
            if (r < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    printf("Timeout – no response\n");
                    break;
                }
                fprintf(stderr, "recvfrom: %s\n", strerror(errno));
                free(answered);
                free(sent_ts);
                free(rx);
                free(tx);
                close(fd);
                return EXIT_FAILURE;
            }

            const echo_hdr *rh = parse_echo_reply(rx, r, raw, family, reply_type);
            if (!rh) continue;
            if (raw && rh->id != hdr->id) continue; /* datagram sockets are
                                                       pre-filtered by the kernel */
            unsigned seq = ntohs(rh->seq);
            if (seq >= (unsigned)sent || answered[seq]) continue;
            answered[seq] = 1;

            struct timespec te;
            clock_gettime(CLOCK_MONOTONIC, &te);
            double rtt_ms = (double)(te.tv_sec - sent_ts[seq].tv_sec) * 1000.0 +
                            (double)(te.tv_nsec - sent_ts[seq].tv_nsec) / 1e6;
            record_rtt(&replies, &rtt_sum, &rtt_min, &rtt_max, rtt_ms);
            print_reply(r, &src, seq, rh->type, rtt_ms);
        }
        free(answered);
        free(sent_ts);
    } else {
        for (int i = 0; i < cfg->count; i++) {
            hdr->seq  = htons((uint16_t)i);
            hdr->cksum = 0;
            if (raw && family == AF_INET)
                hdr->cksum = checksum(hdr, icmp_len); /* IP header is static */

            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            if (sendto(fd, tx, tx_len, 0, (struct sockaddr *)&ctx.dst,
                       ctx.dst_len) < 0) {
                fprintf(stderr, "sendto: %s\n", strerror(errno));
                break;
            }
            sent++;

            while (1) {
                struct sockaddr_storage src;
                socklen_t sl = sizeof src;
                ssize_t r = recvfrom(fd, rx, ctx.rx_cap, 0,
                                     (struct sockaddr *)&src, &sl);
                if (r < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        printf("Timeout – no response\n");
                        break;
                    }
                    fprintf(stderr, "recvfrom: %s\n", strerror(errno));
                    free(rx);
                    free(tx);
                    close(fd);
                    return EXIT_FAILURE;
                }

                const echo_hdr *rh = parse_echo_reply(rx, r, raw, family, reply_type);
                if (!rh) continue;
                if (raw && rh->id != hdr->id) continue;
                if (rh->seq != hdr->seq) continue;

                struct timespec te;
                clock_gettime(CLOCK_MONOTONIC, &te);
                double rtt_ms = (double)(te.tv_sec - ts.tv_sec) * 1000.0 +
                                (double)(te.tv_nsec - ts.tv_nsec) / 1e6;
                record_rtt(&replies, &rtt_sum, &rtt_min, &rtt_max, rtt_ms);
                print_reply(r, &src, ntohs(rh->seq), rh->type, rtt_ms);
                break;
            }

            if (i + 1 < cfg->count)
                sleep_ms(cfg->interval_ms);
        }
    }

    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double total_s = (double)(t1.tv_sec - t0.tv_sec) +
                     (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

    if (replies)
        printf("Ping done: %d/%d (%.1f%%) succeeded, "
               "rtt min/avg/max = %.2f/%.2f/%.2f ms\n",
               replies, sent, 100.0 * replies / sent,
               rtt_min, rtt_sum / replies, rtt_max);
    else
        printf("Ping done: %d/%d (0.0%%) succeeded in %.2f s\n",
               replies, sent, total_s);

    free(rx);
    free(tx);
    close(fd);
    return replies ? EXIT_SUCCESS : EXIT_FAILURE;
}

int resolve_target(const ping_config *cfg, struct sockaddr_storage *out,
                   socklen_t *out_len)
{
    const char *host = cfg->host ? cfg->host : "localhost";
    struct addrinfo hints = {
        .ai_family   = cfg->family,
        .ai_socktype = SOCK_DGRAM,
    };
    struct addrinfo *res = NULL;
    int g = getaddrinfo(host, NULL, &hints, &res);
    if (g != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(g));
        return -1;
    }
    if (!res) {
        freeaddrinfo(res);
        return -1;
    }

    memcpy(out, res->ai_addr, res->ai_addrlen);
    *out_len = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}
