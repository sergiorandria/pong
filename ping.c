/*Copyright (c) 2025 Sergio Randriamihoatra.
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

#include <arpa/inet.h>
#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <asm-generic/socket.h>
#include <bits/getopt_core.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#define ICMP_PACKET_CNT  30
#define ICMP_PACKET_DATA 32

/**
 * @brief Represents a network endpoint with address, port, and liveness state.
 */
typedef struct {
    struct sockaddr_in  sockaddr;
    struct sockaddr_in6 sockaddr6;
    struct sockaddr    *endpointNetmask;
    struct sockaddr    *broadAddr;

    int  src_port;
    int  dst_port;

    _Bool isAlive;
} NetworkEndpoint;

bool ip_address_given;
bool port_given;

static int   ConvertStrToInt(const char *str_ipaddr);
static void  InitEndpoint(char *ip_addr, int port, NetworkEndpoint *endpoint);
static char *getCurrentIpv4Addr(void);
static char *getCurrentIpv6Addr(void);
static bool  checkIfName(char *ifname);

static bool input_ipv6_addr = false;
static bool input_ipv4_addr = false;

/* ────────────────────────────────────────────────────────────────────────────
 * Checksum helpers
 * ──────────────────────────────────────────────────────────────────────────*/

/**
 * @brief Standard Internet checksum (RFC 1071), 16-bit accumulator.
 *
 * @param addr  Pointer to the data buffer.
 * @param len   Length in bytes.
 * @return      One's complement checksum, or (unsigned short)-1 on NULL input.
 */
unsigned short csum(unsigned short *addr, int len)
{
    int sum = 0;

    if (!addr) {
        fprintf(stderr, "csum: NULL pointer\n");
        return (unsigned short)-1;
    }

    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1)
        sum += *(unsigned char *)addr;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

/**
 * @brief Optimised Internet checksum using a 32-bit accumulator.
 *
 * Processes four bytes per iteration, reducing loop overhead on 32/64-bit
 * hosts.  Produces the same result as @ref csum.
 *
 * @param addr  Pointer to the data buffer.
 * @param len   Length in bytes.
 * @return      One's complement checksum, or (unsigned short)-1 on NULL input.
 */
unsigned short csum2(unsigned short *addr, int len)
{
    if (!addr) {
        fprintf(stderr, "csum2: NULL pointer\n");
        return (unsigned short)-1;
    }

    uint32_t sum  = 0;
    uint32_t *p32 = (uint32_t *)addr;

    /* Accumulate 32-bit words. */
    while (len > 3) {
        uint32_t w;
        memcpy(&w, p32++, 4);   /* avoid strict-aliasing UB */
        sum += w;
        if (sum < w) sum++;     /* propagate carry */
        len -= 4;
    }

    /* Handle trailing 16-bit word. */
    addr = (unsigned short *)p32;
    if (len > 1) {
        sum += *addr++;
        len -= 2;
    }

    /* Handle trailing byte. */
    if (len == 1)
        sum += *(unsigned char *)addr;

    /* Fold 32-bit sum into 16 bits. */
    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

/* ────────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ──────────────────────────────────────────────────────────────────────────*/

/**
 * @brief Initialise a NetworkEndpoint from a string IP address and port.
 *
 * When @p ip_addr is NULL the endpoint defaults to the loopback address for
 * both address families.
 *
 * @param ip_addr  Dotted-decimal IPv4 or colon-separated IPv6 string, or NULL.
 * @param port     Port number (host byte order).
 * @param endpoint Output endpoint structure; must not be NULL.
 */
static void InitEndpoint(char *ip_addr, int port, NetworkEndpoint *endpoint)
{
    endpoint->isAlive = false;

    /* ── IPv4 ── */
    endpoint->sockaddr.sin_family = AF_INET;
    endpoint->sockaddr.sin_port   = htons(port);

    if (ip_addr)
        endpoint->sockaddr.sin_addr.s_addr = inet_addr(ip_addr);
    else
        endpoint->sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* ── IPv6 ── */
    endpoint->sockaddr6.sin6_family   = AF_INET6;
    endpoint->sockaddr6.sin6_port     = htons(port);
    endpoint->sockaddr6.sin6_flowinfo = 0;
    endpoint->sockaddr6.sin6_scope_id = 0;

    if (ip_addr) {
        if (inet_pton(AF_INET6, ip_addr, &endpoint->sockaddr6.sin6_addr) != 1)
            endpoint->sockaddr6.sin6_addr = in6addr_loopback;
    } else {
        endpoint->sockaddr6.sin6_addr = in6addr_loopback;
    }
}

/**
 * @brief Convert a decimal digit string to int.
 *
 * Stops at the first non-digit character.
 *
 * @param str_ipaddr  Input string.
 * @return            Parsed integer value.
 */
static int ConvertStrToInt(const char *str_ipaddr)
{
    int    res = 0;
    size_t len = strlen(str_ipaddr);

    for (int i = 0; i < (int)len && isdigit((unsigned char)str_ipaddr[i]); ++i)
        res = 10 * res + (str_ipaddr[i] - '0');

    return res;
}

/**
 * @brief Return true if the interface name represents a wireless device.
 *
 * Matches any name starting with "wl" (e.g. wlan0, wlp3s0).
 */
static bool checkIfName(char *ifname) { return !strncmp(ifname, "wl", 2); }

/**
 * @brief Return the machine's primary wireless IPv4 address.
 *
 * Iterates all interfaces and returns the first non-loopback AF_INET address
 * whose name passes @ref checkIfName.  The caller must free the returned
 * string.
 *
 * @return Heap-allocated address string, or NULL if none found.
 */
static char *getCurrentIpv4Addr(void)
{
    fprintf(stdout, "Getting current IPv4 address ...\n");

    struct ifaddrs *addrs;
    if (getifaddrs(&addrs) < 0) {
        fprintf(stderr, "getifaddrs: %s\n", strerror(errno));
        return NULL;
    }

    char *result = NULL;
    for (struct ifaddrs *tmp = addrs; tmp; tmp = tmp->ifa_next) {
        if (!tmp->ifa_addr || tmp->ifa_addr->sa_family != AF_INET)
            continue;
        if (!checkIfName(tmp->ifa_name))
            continue;

        struct sockaddr_in *sa = (struct sockaddr_in *)tmp->ifa_addr;
        result = malloc(INET_ADDRSTRLEN);
        if (!result) break;

        strncpy(result, inet_ntoa(sa->sin_addr), INET_ADDRSTRLEN);
        fprintf(stdout, "Current IPv4 address: %s\n", result);
        break;
    }

    freeifaddrs(addrs);

    if (!result)
        fprintf(stderr, "No wireless IPv4 interface found\n");

    return result;
}

/**
 * @brief Return the machine's primary wireless IPv6 address.
 *
 * Skips link-local addresses.  The caller must free the returned string.
 *
 * @return Heap-allocated address string, or NULL if none found.
 */
static char *getCurrentIpv6Addr(void)
{
    fprintf(stdout, "Getting current IPv6 address ...\n");

    struct ifaddrs *addrs;
    if (getifaddrs(&addrs) < 0) {
        fprintf(stderr, "getifaddrs: %s\n", strerror(errno));
        return NULL;
    }

    char *result = NULL;
    for (struct ifaddrs *tmp = addrs; tmp; tmp = tmp->ifa_next) {
        if (!tmp->ifa_addr || tmp->ifa_addr->sa_family != AF_INET6)
            continue;
        if (!checkIfName(tmp->ifa_name))
            continue;

        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)tmp->ifa_addr;
        if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr))
            continue;

        result = malloc(INET6_ADDRSTRLEN);
        if (!result) break;

        inet_ntop(AF_INET6, &sa6->sin6_addr, result, INET6_ADDRSTRLEN);
        fprintf(stdout, "Current IPv6 address: %s\n", result);
        break;
    }

    freeifaddrs(addrs);

    if (!result)
        fprintf(stderr, "No wireless IPv6 interface found\n");

    return result;
}

/* ────────────────────────────────────────────────────────────────────────────
 * Scanner implementations
 * ──────────────────────────────────────────────────────────────────────────*/

/**
 * @brief Probe a host via ICMP Echo (ping) over IPv4.
 *
 * Sends @c ICMP_PACKET_CNT echo-request packets and reports the success rate.
 * A 5-second receive timeout is applied per packet.  Requires a raw socket,
 * so the process must run with CAP_NET_RAW / root.
 *
 * @param endpoint  Target endpoint.  When NULL the function falls back to the
 *                  local machine's wireless address.
 * @return EXIT_SUCCESS on completion, EXIT_FAILURE or -1 on error.
 */
int ScanNetworkEndpointIpv4(NetworkEndpoint *endpoint)
{
    char *current_ipv4 = getCurrentIpv4Addr();
    if (!current_ipv4)
        return -1;

    /* Fall back to local host when no target was specified. */
    NetworkEndpoint local;
    if (!endpoint) {
        fprintf(stderr, "NULL endpoint – falling back to localhost\n");
        memset(&local, 0, sizeof(local));
        local.isAlive                    = true;
        local.sockaddr.sin_family        = AF_INET;
        local.sockaddr.sin_port          = htons(8080);
        local.sockaddr.sin_addr.s_addr   = inet_addr(current_ipv4);
        endpoint = &local;
    }

    struct in_addr target_ip = endpoint->sockaddr.sin_addr;
    struct in_addr host_ip;
    host_ip.s_addr = inet_addr(current_ipv4);

    fprintf(stdout, "Sending ICMP to: %s\n", inet_ntoa(target_ip));

    /* ── Buffer allocation ── */
    int   packet_size = sizeof(struct ip) + sizeof(struct icmp) + ICMP_PACKET_DATA;
    char *send_buf    = malloc(packet_size);
    char *recv_buf    = malloc(packet_size + sizeof(struct ip));

    if (!send_buf || !recv_buf) {
        fprintf(stderr, "Buffer allocation failed: %s\n", strerror(errno));
        free(send_buf);
        free(recv_buf);
        free(current_ipv4);
        return -1;
    }

    memset(send_buf, 0, packet_size);
    memset(recv_buf, 0, packet_size + sizeof(struct ip));

    /* ── Header pointers ── */
    struct ip   *ip_hdr  = (struct ip *)send_buf;
    struct icmp *icmp_hdr = (struct icmp *)(send_buf + sizeof(struct ip));
    memset((char *)(icmp_hdr + 1), 'A', ICMP_PACKET_DATA);

    /* ── Socket setup ── */
    int send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int recv_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (send_fd < 0 || recv_fd < 0) {
        fprintf(stderr, "socket(): %s\n", strerror(errno));
        goto err_socks;
    }

    int opt = 1;
    if (setsockopt(send_fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        fprintf(stderr, "setsockopt IP_HDRINCL: %s\n", strerror(errno));
        goto err_socks;
    }

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(recv_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        fprintf(stderr, "setsockopt SO_RCVTIMEO: %s\n", strerror(errno));
        goto err_socks;
    }

    /* ── Static IP header fields ── */
    ip_hdr->ip_v   = 4;
    ip_hdr->ip_hl  = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(packet_size);
    ip_hdr->ip_id  = htons(getpid() & 0xffff);
    ip_hdr->ip_off = htons(0);
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p   = IPPROTO_ICMP;
    ip_hdr->ip_src = host_ip;
    ip_hdr->ip_dst = target_ip;

    /* ── Static ICMP fields ── */
    icmp_hdr->icmp_type  = ICMP_ECHO;
    icmp_hdr->icmp_code  = 0;
    icmp_hdr->icmp_id    = getpid() & 0xffff;
    icmp_hdr->icmp_seq   = 0;

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_addr   = target_ip,
        .sin_port   = 0,
    };

    int success_count = 0;
    for (int i = 0; i < ICMP_PACKET_CNT; ++i) {
        /* Recompute checksums each iteration (seq changes). */
        ip_hdr->ip_sum        = 0;
        ip_hdr->ip_sum        = csum2((unsigned short *)send_buf, sizeof(struct ip));
        icmp_hdr->icmp_cksum  = 0;
        icmp_hdr->icmp_cksum  = csum2((unsigned short *)icmp_hdr,
                                      sizeof(struct icmp) + ICMP_PACKET_DATA);

        int bytes_sent = sendto(send_fd, send_buf, packet_size, 0,
                                (struct sockaddr *)&dest, sizeof(dest));
        if (bytes_sent < 0) {
            fprintf(stderr, "sendto(%s): %s\n", inet_ntoa(dest.sin_addr),
                    strerror(errno));
            goto err_socks;
        }
        fprintf(stdout, "Sent %d bytes ...\n", bytes_sent);

        struct sockaddr_in src;
        socklen_t src_len = sizeof(src);
        int bytes_recv = recvfrom(recv_fd, recv_buf,
                                  packet_size + sizeof(struct ip), 0,
                                  (struct sockaddr *)&src, &src_len);

        if (bytes_recv < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stdout, "Timeout – no response\n");
                icmp_hdr->icmp_seq++;
                continue;
            }
            fprintf(stderr, "recvfrom: %s\n", strerror(errno));
            goto err_socks;
        }

        /* Parse reply: try IP+ICMP first, fall back to raw ICMP. */
        struct icmp *recv_icmp = NULL;
        if (bytes_recv >= (int)(sizeof(struct ip) + sizeof(struct icmp))) {
            struct ip *recv_ip = (struct ip *)recv_buf;
            if (recv_ip->ip_v == 4 && recv_ip->ip_p == IPPROTO_ICMP) {
                int hl = recv_ip->ip_hl << 2;
                if (hl >= 20 && hl <= bytes_recv - (int)sizeof(struct icmp))
                    recv_icmp = (struct icmp *)(recv_buf + hl);
            }
        }
        if (!recv_icmp && bytes_recv >= (int)sizeof(struct icmp))
            recv_icmp = (struct icmp *)recv_buf;

        fprintf(stdout, "Received %d bytes  from=%s  ttl=%d  seq=%d  type=%d  ",
                bytes_recv, inet_ntoa(target_ip),
                ip_hdr->ip_ttl, icmp_hdr->icmp_seq, icmp_hdr->icmp_type);

        if (recv_icmp && recv_icmp->icmp_type == ICMP_ECHOREPLY) {
            fprintf(stdout, "(ECHO REPLY from %s)\n", inet_ntoa(src.sin_addr));
            success_count++;
        } else if (recv_icmp) {
            fprintf(stdout, "(ICMP type %d – not ECHOREPLY)\n", recv_icmp->icmp_type);
        } else {
            fprintf(stdout, "(failed to parse ICMP)\n");
        }

        icmp_hdr->icmp_seq++;
    }

    fprintf(stdout, "Ping done: %d/%d (%.1f%%) succeeded\n",
            success_count, ICMP_PACKET_CNT,
            100.0f * success_count / ICMP_PACKET_CNT);

    free(send_buf);
    free(recv_buf);
    free(current_ipv4);
    close(send_fd);
    close(recv_fd);
    return EXIT_SUCCESS;

err_socks:
    free(send_buf);
    free(recv_buf);
    free(current_ipv4);
    if (send_fd >= 0) close(send_fd);
    if (recv_fd >= 0) close(recv_fd);
    return EXIT_FAILURE;
}

/**
 * @brief Probe a host via ICMPv6 Echo Request over IPv6.
 *
 * Mirrors the behaviour of @ref ScanNetworkEndpointIpv4 but uses AF_INET6
 * and ICMPv6.  The kernel computes the ICMPv6 pseudo-header checksum
 * automatically for SOCK_RAW / IPPROTO_ICMPV6 sockets.
 *
 * @param endpoint  Target endpoint; must not be NULL.
 * @return EXIT_SUCCESS on completion, EXIT_FAILURE or -1 on error.
 */
int ScanNetworkEndpointIpv6(NetworkEndpoint *endpoint)
{
    assert(endpoint != NULL);

    char *current_ipv6 = getCurrentIpv6Addr();
    if (!current_ipv6)
        return -1;

    /* ── Socket ── */
    int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd < 0) {
        fprintf(stderr, "socket(ICMPv6): %s\n", strerror(errno));
        free(current_ipv6);
        return EXIT_FAILURE;
    }

    /* Ask the kernel to fill in the ICMPv6 checksum (offset = 2). */
    int csum_offset = 2;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_CHECKSUM,
                   &csum_offset, sizeof(csum_offset)) < 0) {
        fprintf(stderr, "setsockopt IPV6_CHECKSUM: %s\n", strerror(errno));
        close(fd);
        free(current_ipv6);
        return EXIT_FAILURE;
    }

    /* Filter: only pass ECHO_REPLY to recvfrom. */
    struct icmp6_filter filter;
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
    setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        fprintf(stderr, "setsockopt SO_RCVTIMEO: %s\n", strerror(errno));
        close(fd);
        free(current_ipv6);
        return -1;
    }

    /* ── Buffers ── */
    int   packet_size = sizeof(struct icmp6_hdr) + ICMP_PACKET_DATA;
    char *send_buf    = malloc(packet_size);
    char *recv_buf    = malloc(packet_size);

    if (!send_buf || !recv_buf) {
        fprintf(stderr, "Buffer allocation failed: %s\n", strerror(errno));
        free(send_buf);
        free(recv_buf);
        close(fd);
        free(current_ipv6);
        return -1;
    }

    memset(send_buf, 0, packet_size);
    memset((char *)(send_buf + sizeof(struct icmp6_hdr)), 'A', ICMP_PACKET_DATA);

    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)send_buf;
    icmp6->icmp6_type       = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_code       = 0;
    icmp6->icmp6_id         = htons(getpid() & 0xffff);
    icmp6->icmp6_seq        = htons(0);

    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &endpoint->sockaddr6.sin6_addr, addr_str, sizeof(addr_str));
    fprintf(stdout, "Sending ICMPv6 to: %s\n", addr_str);

    int success_count = 0;
    for (int i = 0; i < ICMP_PACKET_CNT; ++i) {
        icmp6->icmp6_cksum = 0; /* kernel will recompute */

        int bytes_sent = sendto(fd, send_buf, packet_size, 0,
                                (struct sockaddr *)&endpoint->sockaddr6,
                                sizeof(endpoint->sockaddr6));
        if (bytes_sent < 0) {
            fprintf(stderr, "sendto: %s\n", strerror(errno));
            break;
        }
        fprintf(stdout, "Sent %d bytes ...\n", bytes_sent);

        struct sockaddr_in6 src;
        socklen_t src_len = sizeof(src);
        int bytes_recv = recvfrom(fd, recv_buf, packet_size, 0,
                                  (struct sockaddr *)&src, &src_len);

        if (bytes_recv < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stdout, "Timeout – no response\n");
                icmp6->icmp6_seq = htons(ntohs(icmp6->icmp6_seq) + 1);
                continue;
            }
            fprintf(stderr, "recvfrom: %s\n", strerror(errno));
            break;
        }

        char src_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &src.sin6_addr, src_str, sizeof(src_str));

        if (bytes_recv >= (int)sizeof(struct icmp6_hdr)) {
            struct icmp6_hdr *reply = (struct icmp6_hdr *)recv_buf;
            fprintf(stdout,
                    "Received %d bytes  from=%s  seq=%d  type=%d  ",
                    bytes_recv, src_str,
                    ntohs(reply->icmp6_seq), reply->icmp6_type);

            if (reply->icmp6_type == ICMP6_ECHO_REPLY) {
                fprintf(stdout, "(ECHO REPLY)\n");
                success_count++;
            } else {
                fprintf(stdout, "(ICMPv6 type %d)\n", reply->icmp6_type);
            }
        }

        icmp6->icmp6_seq = htons(ntohs(icmp6->icmp6_seq) + 1);
    }

    fprintf(stdout, "Ping done: %d/%d (%.1f%%) succeeded\n",
            success_count, ICMP_PACKET_CNT,
            100.0f * success_count / ICMP_PACKET_CNT);

    free(send_buf);
    free(recv_buf);
    free(current_ipv6);
    close(fd);
    return EXIT_SUCCESS;
}

/* ────────────────────────────────────────────────────────────────────────────
 * Entry point
 * ──────────────────────────────────────────────────────────────────────────*/

/**
 * @brief Program entry point.
 *
 * Options:
 *   -p, --port \<port\>       Target port (default 8080).
 *   -h, --target_ip \<addr\>  Target address (default: localhost).
 *   -4                       Force IPv4 scan.
 *   -6                       Force IPv6 scan.
 *
 * Root privileges are required for raw socket access.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE.
 */
int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "Root privileges required (try sudo).\n");
        return EXIT_FAILURE;
    }

    int   port         = 8080;
    char *target_ipaddr = NULL;
    ip_address_given = port_given = false;

    static struct option long_opts[] = {
        {"port",      required_argument, 0, 'p'},
        {"target_ip", required_argument, 0, 'h'},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "p:h:46", long_opts, NULL)) != -1) {
        switch (c) {
        case 'p':
            port_given = true;
            port = ConvertStrToInt(optarg);
            break;
        case 'h':
            ip_address_given = true;
            target_ipaddr    = optarg;
            break;
        case '4':
            input_ipv4_addr = true;
            break;
        case '6':
            input_ipv6_addr = true;
            break;
        case '?':
            break;
        default:
            fprintf(stderr, "Usage: ./scan [-p port] [-h ip] [-4|-6]\n");
            return EXIT_FAILURE;
        }
    }

    NetworkEndpoint *endpoint = malloc(sizeof(NetworkEndpoint));
    if (!endpoint) {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    memset(endpoint, 0, sizeof(NetworkEndpoint));
    InitEndpoint(target_ipaddr, port, endpoint);

    int ret;
    if (input_ipv6_addr) {
        ret = ScanNetworkEndpointIpv6(endpoint);
        if (ret != EXIT_SUCCESS)
            fprintf(stderr, "IPv6 scan failed\n");
    } else {
        /* -4 flag or default: IPv4 */
        ret = ScanNetworkEndpointIpv4(endpoint);
        if (ret != EXIT_SUCCESS)
            fprintf(stderr, "IPv4 scan failed\n");
    }

    free(endpoint);
    return ret == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}
