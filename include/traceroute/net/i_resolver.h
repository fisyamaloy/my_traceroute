#pragma once

#include <string>

#include "traceroute/net/address_family.h"
#include "traceroute/net/ip_address.h"

namespace traceroute {
namespace net {

class IResolver {
 public:
  virtual ~IResolver() noexcept = default;

  IResolver(const IResolver&) = delete;
  IResolver& operator=(const IResolver&) = delete;
  IResolver(IResolver&&) = delete;
  IResolver& operator=(IResolver&&) = delete;

  virtual IpAddress resolve(const std::string& host,
                            AddressFamily family) const = 0;

 protected:
  IResolver() noexcept = default;
};

}  // namespace net
}  // namespace traceroute
