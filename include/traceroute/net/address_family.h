#pragma once

namespace traceroute {
namespace net {

enum class AddressFamily {
  kIpv4,
  kIpv6,
};

inline constexpr const char* kIpv6NotImplemented =
    "IPv6 is not implemented yet";

}  // namespace net
}  // namespace traceroute
