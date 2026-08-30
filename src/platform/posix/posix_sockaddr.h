#pragma once

#include <sys/socket.h>

#include "traceroute/net/ip_address.h"

namespace traceroute {
namespace net {
namespace posix {

struct SockAddr {
  sockaddr_storage storage{};
  socklen_t length = 0;

  sockaddr* as_sockaddr() noexcept {
    return reinterpret_cast<sockaddr*>(&storage);
  }
  const sockaddr* as_sockaddr() const noexcept {
    return reinterpret_cast<const sockaddr*>(&storage);
  }
};

SockAddr to_sockaddr(const IpAddress& addr);
IpAddress from_sockaddr(const sockaddr* addr, socklen_t length);

}  // namespace posix
}  // namespace net
}  // namespace traceroute
