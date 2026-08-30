#pragma once

#include "traceroute/net/i_resolver.h"

namespace traceroute {
namespace net {
namespace posix {

class PosixResolver : public IResolver {
 public:
  IpAddress resolve(const std::string& host,
                    AddressFamily family) const override;
};

}  // namespace posix
}  // namespace net
}  // namespace traceroute
