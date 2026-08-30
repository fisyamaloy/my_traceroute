#include "traceroute/net/ip_address.h"

#include <algorithm>
#include <array>
#include <bit>
#include <format>
#include <ranges>
#include <stdexcept>
#include <string>

#include "traceroute/byte_order.h"

namespace traceroute {
namespace net {

IpAddress IpAddress::ipv4_from_host_order(std::uint32_t host_order) noexcept {
  IpAddress addr;
  addr.family_ = AddressFamily::kIpv4;
  write_u32_be(addr.bytes_.data(), host_order);
  return addr;
}

IpAddress IpAddress::ipv4_from_network_order(
    std::uint32_t network_order) noexcept {
  IpAddress addr;
  addr.family_ = AddressFamily::kIpv4;
  const auto bytes =
      std::bit_cast<std::array<std::uint8_t, kIpv4Bytes>>(network_order);
  std::ranges::copy(bytes, addr.bytes_.begin());
  return addr;
}

bool IpAddress::is_unspecified() const noexcept {
  if (is_ipv4()) {
    return read_u32_be(bytes_.data()) == 0;
  }
  if (family_ == AddressFamily::kIpv6) {
    return std::ranges::all_of(bytes_, [](std::uint8_t b) { return b == 0; });
  }
  return false;
}

std::uint32_t IpAddress::ipv4_host_order() const {
  if (!is_ipv4()) {
    throw std::logic_error("IpAddress is not IPv4");
  }
  return read_u32_be(bytes_.data());
}

std::uint32_t IpAddress::ipv4_network_order() const {
  if (!is_ipv4()) {
    throw std::logic_error("IpAddress is not IPv4");
  }
  std::array<std::uint8_t, kIpv4Bytes> bytes{};
  std::ranges::copy_n(bytes_.data(), kIpv4Bytes, bytes.begin());
  return std::bit_cast<std::uint32_t>(bytes);
}

std::string IpAddress::to_string() const {
  if (is_ipv4()) {
    const std::uint32_t host = ipv4_host_order();
    return std::format("{}.{}.{}.{}", (host >> 24) & 0xFFu,
                       (host >> 16) & 0xFFu, (host >> 8) & 0xFFu, host & 0xFFu);
  }
  if (family_ != AddressFamily::kIpv6) {
    throw std::logic_error("IpAddress: unknown family");
  }
  return std::format(
      "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}", read_u16_be(bytes_.data()),
      read_u16_be(bytes_.data() + 2), read_u16_be(bytes_.data() + 4),
      read_u16_be(bytes_.data() + 6), read_u16_be(bytes_.data() + 8),
      read_u16_be(bytes_.data() + 10), read_u16_be(bytes_.data() + 12),
      read_u16_be(bytes_.data() + 14));
}

}  // namespace net
}  // namespace traceroute
