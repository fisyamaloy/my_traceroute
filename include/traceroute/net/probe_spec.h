#pragma once

#include "traceroute/net/address_family.h"

namespace traceroute {
namespace net {

enum class ProbeProtocol {
  kIcmpEcho,
  kUdp,
};

struct ProbeSpec {
  AddressFamily family = AddressFamily::kIpv4;
  ProbeProtocol protocol = ProbeProtocol::kIcmpEcho;
};

inline constexpr const char* kIcmpEchoProbeOnly =
    "only ICMP echo probes are implemented";

// nullptr => implemented. Other combinations: new IProbeChannel in the factory.
inline const char* unimplemented_reason(const ProbeSpec& spec) noexcept {
  if (spec.family != AddressFamily::kIpv4) {
    return kIpv6NotImplemented;
  }
  if (spec.protocol != ProbeProtocol::kIcmpEcho) {
    return kIcmpEchoProbeOnly;
  }
  return nullptr;
}

}  // namespace net
}  // namespace traceroute
