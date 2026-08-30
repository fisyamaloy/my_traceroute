#pragma once

#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include "traceroute/net/ip_address.h"
#include "traceroute/net/received_packet.h"
#include "traceroute/packet/checksum.h"
#include "traceroute/packet/icmpv4.h"
#include "traceroute/packet/ipv4.h"

namespace traceroute {
namespace test {

inline net::IpAddress ipv4(std::uint32_t a, std::uint32_t b, std::uint32_t c,
                           std::uint32_t d) {
  return net::IpAddress::ipv4_from_host_order((a << 24) | (b << 16) | (c << 8) |
                                              d);
}

inline void put_icmp_checksum(std::vector<std::uint8_t>& pkt) {
  pkt[packet::kIcmpChecksumOffset] = 0;
  pkt[packet::kIcmpChecksumOffset + 1] = 0;
  const auto sum = packet::internet_checksum(pkt);
  pkt[packet::kIcmpChecksumOffset] = static_cast<std::uint8_t>(sum >> 8);
  pkt[packet::kIcmpChecksumOffset + 1] = static_cast<std::uint8_t>(sum);
}

inline std::vector<std::uint8_t> as_echo_reply(std::vector<std::uint8_t> echo) {
  echo[packet::kIcmpTypeOffset] =
      static_cast<std::uint8_t>(packet::Icmpv4Type::kEchoReply);
  put_icmp_checksum(echo);
  return echo;
}

inline std::vector<std::uint8_t> wrap_ipv4(
    const net::IpAddress& src, const net::IpAddress& dst,
    const std::vector<std::uint8_t>& payload) {
  std::vector<std::uint8_t> ip(packet::kIpv4MinHeaderBytes + payload.size(), 0);
  ip[packet::kIpv4VersionIhlOffset] = packet::kIpv4VersionIhlMinHeader;
  ip[packet::kIpv4ProtocolOffset] = packet::kIpProtoIcmp;
  const std::uint32_t src_net = src.ipv4_network_order();
  const std::uint32_t dst_net = dst.ipv4_network_order();
  std::memcpy(ip.data() + packet::kIpv4SrcAddrOffset, &src_net,
              sizeof(src_net));
  std::memcpy(ip.data() + packet::kIpv4DstAddrOffset, &dst_net,
              sizeof(dst_net));
  if (!payload.empty()) {
    std::memcpy(ip.data() + packet::kIpv4MinHeaderBytes, payload.data(),
                payload.size());
  }
  return ip;
}

inline std::vector<std::uint8_t> icmp_error(
    packet::Icmpv4Type type, std::uint8_t code,
    const std::vector<std::uint8_t>& inner_ip) {
  std::vector<std::uint8_t> icmp(packet::kIcmpHeaderBytes + inner_ip.size(), 0);
  icmp[packet::kIcmpTypeOffset] = static_cast<std::uint8_t>(type);
  icmp[packet::kIcmpCodeOffset] = code;
  std::memcpy(icmp.data() + packet::kIcmpHeaderBytes, inner_ip.data(),
              inner_ip.size());
  put_icmp_checksum(icmp);
  return icmp;
}

inline net::ReceivedPacket packet_from(const net::IpAddress& src,
                                       std::vector<std::uint8_t> bytes) {
  net::ReceivedPacket packet;
  packet.source = src;
  packet.bytes = std::move(bytes);
  return packet;
}

}  // namespace test
}  // namespace traceroute
