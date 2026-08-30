#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "traceroute/net/byte_span.h"
#include "traceroute/net/ip_address.h"
#include "traceroute/packet/probe_reply.h"

namespace traceroute {
namespace packet {

enum class Icmpv4Type : std::uint8_t {
  kEchoReply = 0,
  kDestUnreachable = 3,
  kEchoRequest = 8,
  kTimeExceeded = 11,
};

enum class Icmpv4TimeExceededCode : std::uint8_t {
  kTtl = 0,
  kReassembly = 1,
};

enum class Icmpv4UnreachCode : std::uint8_t {
  kNet = 0,
  kHost = 1,
  kProtocol = 2,
  kPort = 3,
  kNeedFrag = 4,
  kSrcFail = 5,
  kNetUnknown = 6,
  kHostUnknown = 7,
  kIsolated = 8,
  kNetProhibited = 9,
  kHostProhibited = 10,
  kNetTos = 11,
  kHostTos = 12,
  kFiltered = 13,
  kPrecViolation = 14,
  kPrecCutoff = 15,
};

// ICMP header is always 8 bytes (RFC 792). Then a type-specific payload.
constexpr std::size_t kIcmpHeaderBytes = 8;
constexpr std::size_t kIcmpTypeOffset = 0;
constexpr std::size_t kIcmpCodeOffset = 1;
constexpr std::size_t kIcmpChecksumOffset = 2;
// Echo Request/Reply: Identifier and Sequence Number sit in "rest of header".
constexpr std::size_t kIcmpEchoIdOffset = 4;
constexpr std::size_t kIcmpEchoSeqOffset = 6;
// Echo Request and Echo Reply use code 0.
constexpr std::uint8_t kIcmpEchoCode = 0;
// Bytes after the ICMP header in our Echo Request. RFC 792 allows any data.
constexpr std::size_t kEchoPayloadBytes = 32;

struct Icmpv4Echo {
  std::uint16_t id = 0;
  std::uint16_t seq = 0;
};

[[nodiscard]] std::vector<std::uint8_t> build_echo_request(
    std::uint16_t id, std::uint16_t seq, net::ByteSpan payload);

// Reconstruct Time Exceeded / Dest Unreachable from a quoted original
// datagram (IPv4+ICMP or bare ICMP). Linux IP_RECVERR uses this.
// Fills a valid ICMP checksum so the packet is well-formed; see
// match_ipv4_probe_reply for why receive-side checksum is not required.
[[nodiscard]] std::vector<std::uint8_t> wrap_quoted_as_icmp_error(
    std::uint8_t type, std::uint8_t code, net::ByteSpan quoted);

// Match Echo Reply / Time Exceeded / Dest Unreachable for our id/seq.
// Does not verify the ICMP checksum field: Darwin SOCK_DGRAM already
// validated the packet in-kernel, and the userspace buffer often contains
// a garbage checksum and padding. Requiring a valid checksum drops every
// reply (all hops print "*").
[[nodiscard]] std::optional<ProbeReply> match_ipv4_probe_reply(
    net::ByteSpan datagram, const net::IpAddress& recvfrom_src,
    std::uint16_t expect_id, std::uint16_t expect_seq);

}  // namespace packet
}  // namespace traceroute
