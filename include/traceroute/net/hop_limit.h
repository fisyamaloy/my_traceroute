#pragma once

namespace traceroute {
namespace net {

// IPv4 TTL / IPv6 hop limit is one byte on the wire.
constexpr int kMinHopLimit = 1;
constexpr int kMaxHopLimit = 255;

}  // namespace net
}  // namespace traceroute
