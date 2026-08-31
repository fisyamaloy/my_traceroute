#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "traceroute/net/byte_span.h"
#include "traceroute/net/hop_limit.h"
#include "traceroute/net/ip_address.h"

namespace traceroute {
namespace packet {

// IPv4 header (RFC 791). Lengths in bytes unless noted.
constexpr int kIpv4Version = 4;
constexpr std::uint8_t kIpv4IhlMask = 0x0F;
constexpr int kIpv4IhlWordBytes = 4;  // IHL counts 32-bit words
constexpr std::size_t kIpv4MinHeaderBytes = 20;
// First header byte 0x45 = version 4, IHL 5 (20 bytes, no options).
constexpr std::uint8_t kIpv4VersionIhlMinHeader = 0x45;

constexpr std::size_t kIpv4VersionIhlOffset = 0;
constexpr std::size_t kIpv4TotalLengthOffset = 2;
constexpr std::size_t kIpv4ProtocolOffset = 9;
constexpr std::size_t kIpv4SrcAddrOffset = 12;
constexpr std::size_t kIpv4DstAddrOffset = 16;

// IPv4 Protocol field. 1 = ICMP (IANA).
constexpr std::uint8_t kIpProtoIcmp = 1;

using net::kMaxHopLimit;
using net::kMinHopLimit;

inline int ipv4_version(std::uint8_t version_ihl) noexcept {
  return static_cast<int>(version_ihl >> 4);
}

inline int ipv4_header_bytes(std::uint8_t version_ihl) noexcept {
  return static_cast<int>(version_ihl & kIpv4IhlMask) * kIpv4IhlWordBytes;
}

struct Ipv4HeaderView {
  int header_bytes = 0;
  std::uint16_t total_length = 0;
  std::uint8_t protocol = 0;
  net::IpAddress src;
  net::IpAddress dst;
};

[[nodiscard]] std::optional<Ipv4HeaderView> parse_ipv4_header(
    const net::ByteSpan datagram) noexcept;

}  // namespace packet
}  // namespace traceroute
