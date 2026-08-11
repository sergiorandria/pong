# pong

A lightweight, dependency-free network reachability scanner that uses ICMP echo
requests (ping) to check whether endpoints are up. It supports IPv4 and IPv6,
works without root, spaces probes 1 second apart by default, and can blast the
full payload in a single burst (`--flood`). `.onion` / `.i2p` hidden-service
addresses are probed through a SOCKS5 proxy.

## Features

- ICMP echo request scanning for IPv4 **and** IPv6
- **1 second between probes by default** (`-i/--interval`, in ms)
- **`-f/--flood`**: send the full payload (all `-c count` probes) in one
  back-to-back burst — no 1 s overhead between requests — then collect replies
- Raw sockets automatically when `CAP_NET_RAW` is present; otherwise falls back
  to unprivileged ICMP datagram sockets — **no root required**
- IPv6 link-local addresses with scope identifiers (`fe80::…%eth0`)
- Configurable probe count, per-probe timeout, and port
- `.onion` (Tor) and `.i2p` address probing via SOCKS5 proxy (auto-detects a
  local Tor/i2p daemon)
- Fast RFC 1071 checksum with an x86-64 SIMD inner loop
- Per-probe and aggregate statistics (success rate, min/avg/max RTT)

## Requirements

- Linux operating system
- GCC or Clang
- Standard C libraries (POSIX sockets)
- No root privileges required; `sudo setcap cap_net_raw+ep` optionally enables
  the raw socket path

## Building

```bash
make            # release build → ./pong
make debug      # ASan/UBSan instrumented build
make native     # -march=native (fastest, host-specific)
make check      # rebuild with -Werror and run the smoke tests
make install    # install to /usr/local/bin (override PREFIX=/usr)
make clean      # remove build artifacts
```

Optional overrides: `make BUILD=debug ARCH=native WERROR=1`.

## Usage

```bash
./pong [OPTIONS]
```

### Command-Line Options

| Option | Long Option | Description | Default |
|--------|-------------|-------------|---------|
| `-h` | `--target_ip` | Target: IP, hostname, IPv6 with `%scope`, or `.onion` / `.i2p` address | `localhost` |
| `-p` | `--port` | Target port used for `.onion` / `.i2p` probes | 80 |
| `-c` | `--count` | Number of probes | 30 |
| `-t` | `--timeout` | Per-probe timeout in seconds | 5 |
| `-i` | `--interval` | Delay between probes in milliseconds | 1000 |
| `-f` | `--flood` | Send the full payload in one burst (no interval) | off |
| `-P` | `--proxy` | SOCKS5 proxy `host[:port]` for `.onion` / `.i2p` probes | auto |
| `-4` | | Force IPv4 (ICMP only) | auto |
| `-6` | | Force IPv6 (ICMP only) | auto |

### Examples

Ping localhost, 30 probes, 1 second apart (defaults):

```bash
./pong
```

Ping a specific address with only 3 probes:

```bash
./pong -h 192.168.1.100 -c 3
```

Space probes 200 ms apart:

```bash
./pong -h 192.168.1.100 -i 200
```

Blast the full 100-packet payload in a single burst (no 1 s overhead):

```bash
./pong -h 192.168.1.100 -c 100 -f
```

Ping a link-local IPv6 neighbor:

```bash
./pong -h 'fe80::215:5dff:fe00:1%eth0'
```

Probe a Tor hidden service through a local Tor daemon:

```bash
./pong -h 'okduskgytldkxiuqc6.onion' -p 80
```

Probe through a SOCKS5 proxy on a custom address/port:

```bash
./pong -h 'okduskgytldkxiuqc6.onion' -P '127.0.0.1:9050'
```

## How It Works

1. **Address resolution**: the target is resolved with `getaddrinfo`,
   supporting IPv4, IPv6, and IPv6 scope IDs.
2. **Socket selection**: if `CAP_NET_RAW` is in the process effective set
   (checked via the raw `capget` syscall, no libcap dependency), a raw socket is
   opened and the tool builds the IP + ICMP headers itself. Otherwise it uses
   unprivileged ICMP datagram sockets, whose headers the kernel fills in.
3. **Packet construction**: builds an ICMP echo request (8 + 32 bytes payload)
   with proper RFC 1071 checksums — the ICMP checksum in userspace, and the IP
   header checksum too when the raw IPv4 path is used. ICMPv6 checksums are left
   to the kernel.
4. **Paced mode** (default): one probe is sent, its reply awaited (up to
   `-t`), then the tool sleeps `-i` ms (default 1000) before the next request.
5. **Flood mode** (`-f`): all `-c` probes are sent back-to-back with no
   interval — each recording its own send timestamp — then replies are matched
   by sequence number until every probe is answered or the timeout window
   elapses.
6. **Reply processing**: filters for matching echo-reply type, ID, and sequence,
   and records the RTT.
7. **Statistics**: reports the success rate and min/avg/max RTT.

For `.onion` / `.i2p` targets the tool performs the ICMP-over-Tor/i2p
equivalent: it connects to the local SOCKS5 proxy and issues a `CONNECT` for the
target. Success is determined by the proxy handshake outcome — the proxy only
connects when the hidden service is reachable. `--flood` is not applicable there
and is ignored with a notice.

## Project Structure

```
pong/
├── Makefile            # release/debug/native/check/install targets
├── README.md
├── LICENSE
├── src/
│   ├── main.c          # CLI parsing, config, orchestration
│   ├── ping.c          # ICMP/ICMPv6 scan engine (paced + flood modes)
│   ├── ping.h          # ping_config type, scan_address/resolve_target API
│   ├── socks5.c        # SOCKS5 CONNECT probing, proxy host:port parsing
│   ├── socks5.h
│   ├── checksum.c      # RFC 1071 checksum (x86-64 SIMD inner loop)
│   ├── checksum.h
│   ├── util.c          # parsing, address/capability helpers, socket I/O
│   └── util.h
└── tests/
    └── smoke.sh        # functional smoke test suite (make check)
```

## Technical Details

### Checksum

The RFC 1071 Internet checksum is computed over the packet as 8-byte words into
a 64-bit accumulator with end-around carry folding on every addition. On x86-64
the inner loop is inline assembly using the `ADC` instruction (which chains the
carry flag across additions), unrolled four words per iteration. A portable
unrolled-by-four fallback is used on other architectures.

### Build Flags

The release build uses `-O3 -flto -fno-plt` plus standard hardening:
`-fstack-protector-strong -fPIE -pie` with full RELRO and a non-executable
stack, and `-D_FORTIFY_SOURCE=2`. The debug build is `-O0 -g3` with AddressSanitizer
and UndefinedBehaviorSanitizer. `make check` compiles with `-Werror` alongside a
strict warning set (`-Wall -Wextra -Wpedantic -Wshadow -Wwrite-strings
-Wmissing-prototypes -Wformat=2 …`) and runs the smoke suite.

## Output

```
Pinging 127.0.0.1 (IPv4) via unprivileged ICMP datagram socket
Received 40 bytes  from=127.0.0.1  seq=0  type=0  rtt=0.04 ms  (ECHO REPLY)
Received 40 bytes  from=127.0.0.1  seq=1  type=0  rtt=0.05 ms  (ECHO REPLY)
Received 40 bytes  from=127.0.0.1  seq=2  type=0  rtt=0.06 ms  (ECHO REPLY)
Ping done: 3/3 (100.0%) succeeded, rtt min/avg/max = 0.04/0.05/0.05 ms
```

## Error Handling

- Socket creation failures (with a hint to enable unprivileged ICMP)
- Send/recv failures
- Timeouts (no response)
- Invalid proxy specifications
- Unresolvable hosts
- Memory allocation failures

## Enabling the Fast Path

Unprivileged ICMP datagram sockets work out of the box on most systems. To use
raw sockets instead:

```bash
# Allow unprivileged ICMP (kernel 4.11+), if not already enabled
sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'

# Or grant raw socket capability to the binary
sudo setcap cap_net_raw+ep ./pong
```

## Limitations

- `.onion` / `.i2p` probes require a running local SOCKS5 proxy (Tor or i2pd)
  unless overridden with `-P`.
- `--flood` applies to ICMP probes only; it is ignored (with a notice) for
  `.onion` / `.i2p` targets.
- Some networks block ICMP entirely.

## Security Considerations

⚠️ **Warning**: This tool sends network probes. Use responsibly and only on
networks you own or have permission to scan.

- Raw socket access can be a security risk
- Ensure proper network permissions before scanning
- May trigger intrusion detection systems
- Some networks block ICMP packets

## Troubleshooting

### "socket(AF_INET, ICMP): Operation not permitted"
Your kernel does not allow unprivileged ICMP sockets and you lack `CAP_NET_RAW`.
Run:

```bash
sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'
```

or grant the capability:

```bash
sudo setcap cap_net_raw+ep ./pong
```

### Timeouts
- Verify the target IP is correct and reachable
- Check firewall rules on both source and destination
- Verify the target responds to ICMP requests
- Some hosts have ICMP disabled

### `.onion` / `.i2p` probes all time out
- Ensure a local Tor/i2p SOCKS5 proxy is running (Tor default: `127.0.0.1:9050`)
- Specify it explicitly with `-P`

## License

This is educational/demonstration code. Use at your own risk and ensure
compliance with local laws and network policies.

## Disclaimer

This tool is provided for educational and network administration purposes only.
Always obtain proper authorization before scanning networks. Unauthorized
network scanning may be illegal in your jurisdiction.

## Author

Sergio Randriamihoatra <sergiorandriamihoatra@gmail.com>

## Version

3.0.0
