# traceroute

Console analog of traceroute: IPv4 ICMP Echo probes on Linux and macOS.
macOS uses `SOCK_DGRAM`/`IPPROTO_ICMP` (no root). Linux tries `SOCK_RAW` first
(works as root / `CAP_NET_RAW`), then the same unprivileged datagram socket.

## Build

Requires CMake 3.16+, a C++20 compiler, and Git (Catch2 is fetched for tests).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```


## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Destination answered (Echo Reply or ICMP Dest Unreachable) |
| 1 | Max TTL reached, or a runtime error (resolve / socket) |
| 2 | Bad CLI (`--help` is 0) |

## Run

```sh
./build/traceroute example.com
./build/traceroute -m 20 -q 3 -w 2 8.8.8.8
./build/traceroute --help
```

### Linux ICMP datagram sockets

Unprivileged ping sockets need the process group in `net.ipv4.ping_group_range`.
If `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` fails:

```sh
sudo sysctl net.ipv4.ping_group_range='0 2147483647'
```

macOS accepts this socket type without extra sysctl.

## Tests

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Or run the binary directly:

```sh
./build/tests/traceroute_tests
```

Coverage: ICMP parse/checksum (including Linux errqueue reconstruct and IHL>5),
CLI, TTL loop (mocked `IProbeChannel`), numeric resolver.
Receive matching does **not** require a valid ICMP checksum: Darwin `SOCK_DGRAM`
already verified the packet, and the userspace buffer often has a garbage
checksum.

A hop that answers without a source address (empty `SO_EE_OFFENDER`) is printed
as `???` plus RTT, not `*`. IPv4 literals are resolved with `AI_NUMERICHOST`
first so `8.8.8.8` does not wait on DNS.
