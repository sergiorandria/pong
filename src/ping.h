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

#ifndef PONG_PING_H
#define PONG_PING_H

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>

#define PING_PACKET_CNT   30
#define PING_DATA_SIZE    32
#define PING_TIMEOUT_S    5
#define PING_INTERVAL_MS  1000
#define PING_DEFAULT_PORT 80
#define PING_RX_CAP       2048

typedef struct {
    int    family;        /* AF_INET / AF_INET6 / AF_UNSPEC */
    char  *host;          /* target: IP, hostname, .onion or .i2p */
    int    port;          /* port used for .onion / .i2p probes */
    int    count;         /* number of probes */
    int    timeout_s;     /* per-probe timeout */
    int    interval_ms;   /* delay between probes (0 = none) */
    bool   flood;         /* send the full payload in a single burst */
    char  *proxy;         /* optional SOCKS5 proxy for .onion/.i2p */
} ping_config;

/* Resolve @cfg->host (default "localhost") into a sockaddr. */
int resolve_target(const ping_config *cfg, struct sockaddr_storage *out,
                   socklen_t *out_len);

/* Run the ICMP/ICMPv6 scan against @dst; prints per-probe and aggregate
 * results, returns EXIT_SUCCESS if at least one reply was seen. */
int scan_address(int family, const struct sockaddr_storage *dst,
                 socklen_t dst_len, const ping_config *cfg);

#endif /* PONG_PING_H */
