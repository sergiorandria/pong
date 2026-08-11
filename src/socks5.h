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

#ifndef PONG_SOCKS5_H
#define PONG_SOCKS5_H

#include "ping.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TOR_SOCKS_HOST "127.0.0.1"
#define TOR_SOCKS_PORT 9050
#define I2P_SOCKS_HOST "127.0.0.1"
#define I2P_SOCKS_PORT 4447

/* One SOCKS5 CONNECT probe against @host:@port through @proxy_host:@proxy_port.
 * Returns 0 = reachable, 1 = proxy replied but the target connect failed,
 *        -1 = proxy unreachable / handshake failure. */
int probe_socks5(const char *host, uint16_t port, const char *proxy_host,
                 uint16_t proxy_port, int timeout_s);

/* Split "[host]:port", "host:port" or "host" into @host / @port. */
int parse_hostport(const char *s, char *host, size_t host_cap,
                   uint16_t *port, uint16_t def);

/* Run a full .onion / .i2p reachability scan; prints results and returns
 * EXIT_SUCCESS if at least one probe succeeded. */
int scan_onion_i2p(const ping_config *cfg, bool onion);

#endif /* PONG_SOCKS5_H */
