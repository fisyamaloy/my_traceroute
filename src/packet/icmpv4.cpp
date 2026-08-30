#include "traceroute/packet/icmpv4.h"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <vector>

#include "traceroute/byte_order.h"
#include "traceroute/packet/checksum.h"
#include "traceroute/packet/ipv4.h"

namespace traceroute {
namespace packet {
namespace {

std::optional<Icmpv4Echo> echo_id_seq(net::ByteSpan icmp) {
  if (icmp.size() < kIcmpHeaderBytes) {
    return std::nullopt;
  }
  return Icmpv4Echo{
      .id = read_u16_be(icmp.data() + kIcmpEchoIdOffset),
      .seq = read_u16_be(icmp.data() + kIcmpEchoSeqOffset),
  };
}

bool is_our_echo_request(net::ByteSpan icmp, std::uint16_t expect_id,
                         std::uint16_t expect_seq) {
  if (icmp.size() < kIcmpHeaderBytes) {
    return false;
  }
  if (static_cast<Icmpv4Type>(icmp[kIcmpTypeOffset]) !=
          Icmpv4Type::kEchoRequest ||
      icmp[kIcmpCodeOffset] != kIcmpEchoCode) {
    return false;
  }
  const auto echo = echo_id_seq(icmp);
  return echo && echo->id == expect_id && echo->seq == expect_seq;
}

bool looks_like_ipv4_icmp(net::ByteSpan datagram) {
  if (datagram.size() < kIpv4MinHeaderBytes) {
    return false;
  }
  if (ipv4_version(datagram[kIpv4VersionIhlOffset]) != kIpv4Version) {
    return false;
  }
  const int ihl = ipv4_header_bytes(datagram[kIpv4VersionIhlOffset]);
  if (ihl < static_cast<int>(kIpv4MinHeaderBytes) ||
      datagram.size() < static_cast<std::size_t>(ihl) + kIcmpHeaderBytes) {
    return false;
  }
  return datagram[kIpv4ProtocolOffset] == kIpProtoIcmp;
}

net::ByteSpan icmp_bytes_from_ipv4(net::ByteSpan datagram,
                                   const Ipv4HeaderView& ip) {
  const auto header = static_cast<std::size_t>(ip.header_bytes);
  std::size_t icmp_len = datagram.size() - header;
  if (ip.total_length > header &&
      static_cast<std::size_t>(ip.total_length) <= datagram.size()) {
    icmp_len = static_cast<std::size_t>(ip.total_length) - header;
  }
  return datagram.subspan(header, icmp_len);
}

std::optional<ProbeReply> match_icmp_payload(net::ByteSpan icmp,
                                             const net::IpAddress& responder,
                                             std::uint16_t expect_id,
                                             std::uint16_t expect_seq) {
  using enum Icmpv4Type;

  if (icmp.size() < kIcmpHeaderBytes) {
    return std::nullopt;
  }
  const auto type = static_cast<Icmpv4Type>(icmp[kIcmpTypeOffset]);
  const std::uint8_t code = icmp[kIcmpCodeOffset];

  if (type == kEchoReply) {
    if (code != kIcmpEchoCode) {
      return std::nullopt;
    }
    const auto echo = echo_id_seq(icmp);
    if (!echo || echo->id != expect_id || echo->seq != expect_seq) {
      return std::nullopt;
    }
    return ProbeReply{
        .kind = ProbeReplyKind::kEchoReply,
        .responder = responder,
        .code = code,
    };
  }

  if (type == kTimeExceeded && static_cast<Icmpv4TimeExceededCode>(code) !=
                                   Icmpv4TimeExceededCode::kTtl) {
    return std::nullopt;
  }
  if (type != kTimeExceeded && type != kDestUnreachable) {
    return std::nullopt;
  }

  if (icmp.size() < kIcmpHeaderBytes + kIpv4MinHeaderBytes) {
    return std::nullopt;
  }
  const net::ByteSpan inner = icmp.subspan(kIcmpHeaderBytes);
  const auto inner_ip = parse_ipv4_header(inner);
  if (!inner_ip || inner_ip->protocol != kIpProtoIcmp) {
    return std::nullopt;
  }
  const auto inner_header = static_cast<std::size_t>(inner_ip->header_bytes);
  if (inner.size() < inner_header + kIcmpHeaderBytes) {
    return std::nullopt;
  }
  if (!is_our_echo_request(inner.subspan(inner_header), expect_id,
                           expect_seq)) {
    return std::nullopt;
  }

  return ProbeReply{
      .kind = (type == kTimeExceeded) ? ProbeReplyKind::kTimeExceeded
                                      : ProbeReplyKind::kDestUnreachable,
      .responder = responder,
      .code = code,
  };
}

}  // namespace

std::vector<std::uint8_t> build_echo_request(std::uint16_t id,
                                             std::uint16_t seq,
                                             net::ByteSpan payload) {
  std::vector<std::uint8_t> packet(kIcmpHeaderBytes + payload.size(), 0);
  packet[kIcmpTypeOffset] = static_cast<std::uint8_t>(Icmpv4Type::kEchoRequest);
  packet[kIcmpCodeOffset] = kIcmpEchoCode;
  write_u16_be(packet.data() + kIcmpEchoIdOffset, id);
  write_u16_be(packet.data() + kIcmpEchoSeqOffset, seq);
  if (!payload.empty()) {
    std::ranges::copy(payload, packet.begin() + kIcmpHeaderBytes);
  }
  write_u16_be(packet.data() + kIcmpChecksumOffset, internet_checksum(packet));
  return packet;
}

std::vector<std::uint8_t> wrap_quoted_as_icmp_error(std::uint8_t type,
                                                    std::uint8_t code,
                                                    net::ByteSpan quoted) {
  std::vector<std::uint8_t> inner;
  if (!quoted.empty() && ipv4_version(quoted[0]) == kIpv4Version) {
    inner.assign(quoted.begin(), quoted.end());
  } else {
    inner.assign(kIpv4MinHeaderBytes, 0);
    inner[kIpv4VersionIhlOffset] = kIpv4VersionIhlMinHeader;
    inner[kIpv4ProtocolOffset] = kIpProtoIcmp;
    inner.insert(inner.end(), quoted.begin(), quoted.end());
  }
  std::vector<std::uint8_t> icmp(kIcmpHeaderBytes + inner.size(), 0);
  icmp[kIcmpTypeOffset] = type;
  icmp[kIcmpCodeOffset] = code;
  if (!inner.empty()) {
    std::ranges::copy(
        inner, icmp.begin() + static_cast<std::ptrdiff_t>(kIcmpHeaderBytes));
  }
  write_u16_be(icmp.data() + kIcmpChecksumOffset, internet_checksum(icmp));
  return icmp;
}

std::optional<ProbeReply> match_ipv4_probe_reply(
    net::ByteSpan datagram, const net::IpAddress& recvfrom_src,
    std::uint16_t expect_id, std::uint16_t expect_seq) {
  if (looks_like_ipv4_icmp(datagram)) {
    const auto ip = parse_ipv4_header(datagram);
    if (!ip) {
      return std::nullopt;
    }
    return match_icmp_payload(icmp_bytes_from_ipv4(datagram, *ip), ip->src,
                              expect_id, expect_seq);
  }
  return match_icmp_payload(datagram, recvfrom_src, expect_id, expect_seq);
}

}  // namespace packet
}  // namespace traceroute
