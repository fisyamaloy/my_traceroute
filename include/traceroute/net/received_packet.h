#pragma once

#include <vector>

#include "traceroute/net/ip_address.h"

namespace traceroute {
namespace net {

struct ReceivedPacket {
  IpAddress source;
  std::vector<std::uint8_t> bytes;
};

}  // namespace net
}  // namespace traceroute
