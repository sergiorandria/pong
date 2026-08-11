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

#ifndef PONG_UTIL_H
#define PONG_UTIL_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* Parse a decimal integer in [min, max]; prints an error and returns -1 on
 * any malformed or out-of-range input. */
int parse_int(const char *s, int min, int max, const char *what);

/* Render an AF_INET/AF_INET6 sockaddr into @buf ("?" on unknown families). */
const char *addr_to_str(const struct sockaddr_storage *ss, char *buf,
                        size_t buflen);

/* True if @host ends with @suffix (case-insensitive). */
bool host_has_suffix(const char *host, const char *suffix);
bool is_onion(const char *host);
bool is_i2p(const char *host);

/* True if CAP_NET_RAW is in the process effective set (via the raw capget
 * syscall; falls back to euid==0). */
bool have_cap_net_raw(void);

/* Source address the kernel would use to reach @dst, via a throwaway
 * connected UDP socket. */
bool get_source_ip4(const struct in_addr *dst, struct in_addr *out);

/* Connect a non-blocking TCP socket to @sa with a @timeout_s deadline;
 * returns the blocking fd, or -1. */
int tcp_connect_timeout(const struct sockaddr *sa, socklen_t salen,
                        int timeout_s);

/* Send/recv a full buffer, looping until done or an error. */
ssize_t send_all(int fd, const void *buf, size_t len);
ssize_t recv_exact(int fd, void *buf, size_t len);

/* Sleep for @ms milliseconds (interrupt-safe). */
void sleep_ms(int ms);

#endif /* PONG_UTIL_H */
