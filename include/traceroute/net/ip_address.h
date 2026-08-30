#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>

#include "traceroute/net/address_family.h"

namespace traceroute {
namespace net {

class IpAddress {
 public:
  static IpAddress ipv4_from_host_order(std::uint32_t host_order) noexcept;
  static IpAddress ipv4_from_network_order(
      std::uint32_t network_order) noexcept;

  AddressFamily family() const noexcept { return family_; }
  bool is_ipv4() const noexcept { return family_ == AddressFamily::kIpv4; }
  bool is_unspecified() const noexcept;

  std::uint32_t ipv4_host_order() const;
  std::uint32_t ipv4_network_order() const;

  std::string to_string() const;

  friend bool operator==(const IpAddress&, const IpAddress&) = default;
  friend std::strong_ordering operator<=>(const IpAddress&,
                                          const IpAddress&) = default;

 private:
  AddressFamily family_ = AddressFamily::kIpv4;
  static constexpr std::size_t kStorageBytes = 16;
  static constexpr std::size_t kIpv4Bytes = 4;
  std::array<std::uint8_t, kStorageBytes> bytes_{};
};

}  // namespace net
}  // namespace traceroute
