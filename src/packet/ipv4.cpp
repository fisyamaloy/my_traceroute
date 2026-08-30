#include "traceroute/packet/ipv4.h"

#include <algorithm>
#include <array>
#include <bit>

#include "traceroute/byte_order.h"

namespace traceroute {
namespace packet {

std::optional<Ipv4HeaderView> parse_ipv4_header(net::ByteSpan datagram) {
  if (datagram.size() < kIpv4MinHeaderBytes) {
    return std::nullopt;
  }
  if (ipv4_version(datagram[kIpv4VersionIhlOffset]) != kIpv4Version) {
    return std::nullopt;
  }
  const int ihl = ipv4_header_bytes(datagram[kIpv4VersionIhlOffset]);
  if (ihl < static_cast<int>(kIpv4MinHeaderBytes) ||
      datagram.size() < static_cast<std::size_t>(ihl)) {
    return std::nullopt;
  }

  std::array<std::uint8_t, 4> src_bytes{};
  std::array<std::uint8_t, 4> dst_bytes{};
  std::ranges::copy(datagram.subspan(kIpv4SrcAddrOffset, 4), src_bytes.begin());
  std::ranges::copy(datagram.subspan(kIpv4DstAddrOffset, 4), dst_bytes.begin());
  return Ipv4HeaderView{
      .header_bytes = ihl,
      .total_length = read_u16_be(datagram.data() + kIpv4TotalLengthOffset),
      .protocol = datagram[kIpv4ProtocolOffset],
      .src = net::IpAddress::ipv4_from_network_order(
          std::bit_cast<std::uint32_t>(src_bytes)),
      .dst = net::IpAddress::ipv4_from_network_order(
          std::bit_cast<std::uint32_t>(dst_bytes)),
  };
}

}  // namespace packet
}  // namespace traceroute
