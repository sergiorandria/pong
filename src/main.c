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
#include "socks5.h"
#include "util.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  -h, --target_ip <host>    target: IP, hostname, IPv6 with %%scope,\n"
        "                            or an .onion / .i2p address          [localhost]\n"
        "  -p, --port <port>         target port for .onion/.i2p probes   [80]\n"
        "  -c, --count <n>           number of probes                     [30]\n"
        "  -t, --timeout <s>         per-probe timeout in seconds         [5]\n"
        "  -i, --interval <ms>       delay between probes in ms           [1000]\n"
        "  -f, --flood               send the full payload in one burst   [off]\n"
        "  -P, --proxy <host[:port]> SOCKS5 proxy for .onion/.i2p probes  [auto]\n"
        "  -4                        force IPv4 (ICMP only)\n"
        "  -6                        force IPv6 (ICMP only)\n"
        "\n"
        "No root required: uses raw sockets when CAP_NET_RAW is present, otherwise\n"
        "falls back to unprivileged ICMP datagram sockets.\n"
        "  enable unprivileged ICMP:  sysctl -w net.ipv4.ping_group_range='0 2147483647'\n"
        "  grant raw sockets:         sudo setcap cap_net_raw+ep %s\n",
        prog, prog);
}

int main(int argc, char **argv)
{
    ping_config cfg = {
        .family      = AF_UNSPEC,
        .host        = NULL,
        .port        = PING_DEFAULT_PORT,
        .count       = PING_PACKET_CNT,
        .timeout_s   = PING_TIMEOUT_S,
        .interval_ms = PING_INTERVAL_MS,
        .flood       = false,
        .proxy       = NULL,
    };

    static const struct option long_opts[] = {
        {"target_ip", required_argument, 0, 'h'},
        {"port",      required_argument, 0, 'p'},
        {"count",     required_argument, 0, 'c'},
        {"timeout",   required_argument, 0, 't'},
        {"interval",  required_argument, 0, 'i'},
        {"flood",     no_argument,       0, 'f'},
        {"proxy",     required_argument, 0, 'P'},
        {"ipv4",      no_argument,       0, '4'},
        {"ipv6",      no_argument,       0, '6'},
        {"help",      no_argument,       0, 'H'},
        {0, 0, 0, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "h:p:c:t:i:fP:46", long_opts, NULL)) != -1) {
        int v;
        switch (c) {
        case 'h': cfg.host = optarg; break;
        case 'p':
            if ((v = parse_int(optarg, 1, 65535, "port")) < 0)
                return EXIT_FAILURE;
            cfg.port = v;
            break;
        case 'c':
            if ((v = parse_int(optarg, 1, 100000, "count")) < 0)
                return EXIT_FAILURE;
            cfg.count = v;
            break;
        case 't':
            if ((v = parse_int(optarg, 1, 60, "timeout")) < 0)
                return EXIT_FAILURE;
            cfg.timeout_s = v;
            break;
        case 'i':
            if ((v = parse_int(optarg, 0, 60000, "interval")) < 0)
                return EXIT_FAILURE;
            cfg.interval_ms = v;
            break;
        case 'f': cfg.flood = true; break;
        case 'P': cfg.proxy = optarg; break;
        case '4': cfg.family = AF_INET; break;
        case '6': cfg.family = AF_INET6; break;
        case 'H':
            usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    const char *host = cfg.host ? cfg.host : "localhost";
    bool onion = is_onion(host);
    bool i2p   = is_i2p(host);

    if (cfg.flood && (onion || i2p)) {
        fprintf(stderr, "note: --flood is not supported for .onion/.i2p probes; "
                "ignoring it\n");
        cfg.flood = false;
    }

    int rc;
    if (onion || i2p) {
        rc = scan_onion_i2p(&cfg, onion);
    } else {
        struct sockaddr_storage dst;
        socklen_t dst_len = 0;
        if (resolve_target(&cfg, &dst, &dst_len) < 0)
            return EXIT_FAILURE;
        rc = scan_address(dst.ss_family, &dst, dst_len, &cfg);
    }

    return rc == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}
