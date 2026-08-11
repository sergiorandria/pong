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

#include "socks5.h"

#include "util.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

int probe_socks5(const char *host, uint16_t port,
                 const char *proxy_host, uint16_t proxy_port,
                 int timeout_s)
{
    char port_str[8];
    snprintf(port_str, sizeof port_str, "%u", proxy_port);

    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(proxy_host, port_str, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = tcp_connect_timeout(ai->ai_addr, ai->ai_addrlen, timeout_s);
        if (fd >= 0)
            break;
    }
    freeaddrinfo(res);
    if (fd < 0)
        return -1;

    struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    int rc = -1;
    static const uint8_t greet[] = { 0x05, 0x01, 0x00 }; /* SOCKS5, 1 method, no-auth */
    if (send_all(fd, greet, sizeof greet) != (ssize_t)sizeof greet)
        goto done;

    uint8_t gresp[2];
    if (recv_exact(fd, gresp, 2) != 2 || gresp[0] != 0x05 || gresp[1] != 0x00)
        goto done;

    size_t host_len = strlen(host);
    if (host_len > 255)
        goto done;

    uint8_t req[4 + 1 + 255 + 2];
    size_t off = 0;
    req[off++] = 0x05;              /* VER */
    req[off++] = 0x01;              /* CMD = CONNECT */
    req[off++] = 0x00;              /* RSV */
    req[off++] = 0x03;              /* ATYP = domain name */
    req[off++] = (uint8_t)host_len;
    memcpy(req + off, host, host_len); off += host_len;
    uint16_t pbe = htons(port);
    memcpy(req + off, &pbe, 2); off += 2;

    if (send_all(fd, req, off) != (ssize_t)off)
        goto done;

    uint8_t rresp[4];
    if (recv_exact(fd, rresp, 4) != 4 || rresp[0] != 0x05)
        goto done;
    rc = (rresp[1] == 0x00) ? 0 : 1; /* 0x00 = request granted */

done:
    close(fd);
    return rc;
}

int parse_hostport(const char *s, char *host, size_t host_cap,
                   uint16_t *port, uint16_t def)
{
    if (s[0] == '[') { /* bracketed IPv6 literal: [addr] or [addr]:port */
        const char *close = strchr(s, ']');
        if (!close)
            return -1;
        size_t hl = (size_t)(close - s - 1);
        if (hl == 0 || hl >= host_cap)
            return -1;
        memcpy(host, s + 1, hl);
        host[hl] = '\0';
        if (close[1] == '\0') {
            *port = def;
        } else if (close[1] == ':') {
            char *end;
            long  p = strtol(close + 2, &end, 10);
            if (*end != '\0' || p < 1 || p > 65535)
                return -1;
            *port = (uint16_t)p;
        } else {
            return -1;
        }
        return 0;
    }

    const char *colon = strrchr(s, ':');
    if (colon) {
        size_t hl = (size_t)(colon - s);
        if (hl == 0 || hl >= host_cap)
            return -1;
        memcpy(host, s, hl);
        host[hl] = '\0';
        char *end;
        long  p = strtol(colon + 1, &end, 10);
        if (*end != '\0' || p < 1 || p > 65535)
            return -1;
        *port = (uint16_t)p;
    } else {
        snprintf(host, host_cap, "%s", s);
        *port = def;
    }
    return 0;
}

int scan_onion_i2p(const ping_config *cfg, bool onion)
{
    const char *host       = cfg->host;
    const char *def_proxy  = onion ? TOR_SOCKS_HOST : I2P_SOCKS_HOST;
    uint16_t    def_port   = onion ? TOR_SOCKS_PORT : I2P_SOCKS_PORT;

    char     proxy_host[256];
    uint16_t proxy_port;
    if (cfg->proxy && cfg->proxy[0]) {
        if (parse_hostport(cfg->proxy, proxy_host, sizeof proxy_host,
                           &proxy_port, def_port) < 0) {
            fprintf(stderr, "invalid proxy: %s\n", cfg->proxy);
            return EXIT_FAILURE;
        }
    } else {
        snprintf(proxy_host, sizeof proxy_host, "%s", def_proxy);
        proxy_port = def_port;
    }

    printf("Probing %s:%d via %s SOCKS5 proxy %s:%u\n",
           host, cfg->port, onion ? "Tor" : "i2p", proxy_host, proxy_port);

    int    ok = 0;
    double sum = 0, mn = 0, mx = 0;
    for (int i = 0; i < cfg->count; i++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int rc = probe_socks5(host, (uint16_t)cfg->port,
                              proxy_host, proxy_port, cfg->timeout_s);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double ms = (double)(t1.tv_sec - t0.tv_sec) * 1000.0 +
                    (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;

        if (rc == 0) {
            ok++;
            sum += ms;
            if (ok == 1)
                mn = mx = ms;
            else {
                if (ms < mn) mn = ms;
                if (ms > mx) mx = ms;
            }
        }
        printf("Probe %d: %-14s (%.2f ms)\n", i + 1,
               rc == 0 ? "reachable" : rc == 1 ? "not reachable" : "proxy error", ms);

        if (i + 1 < cfg->count)
            sleep_ms(cfg->interval_ms);
    }

    if (ok)
        printf("Done: %d/%d reachable, rtt min/avg/max = %.2f/%.2f/%.2f ms\n",
               ok, cfg->count, mn, sum / ok, mx);
    else
        printf("Done: %d/%d reachable\n", ok, cfg->count);

    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
