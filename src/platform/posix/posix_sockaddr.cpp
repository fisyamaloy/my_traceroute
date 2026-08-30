#include "posix_sockaddr.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstring>
#include <stdexcept>

namespace traceroute {
namespace net {
namespace posix {

SockAddr to_sockaddr(const IpAddress& addr) {
  if (!addr.is_ipv4()) {
    throw std::logic_error("only IPv4 addresses are supported");
  }
  SockAddr out;
  sockaddr_in v4{};
  v4.sin_family = AF_INET;
  v4.sin_port = 0;
  v4.sin_addr.s_addr = addr.ipv4_network_order();
  std::memcpy(&out.storage, &v4, sizeof(v4));
  out.length = sizeof(v4);
  return out;
}

IpAddress from_sockaddr(const sockaddr* addr, socklen_t length) {
  if (addr == nullptr) {
    throw std::logic_error("from_sockaddr: null address");
  }
  if (length < static_cast<socklen_t>(sizeof(sockaddr_in))) {
    throw std::runtime_error("truncated sockaddr");
  }
  if (addr->sa_family != AF_INET) {
    throw std::runtime_error("unsupported sockaddr family");
  }
  const auto* v4 = reinterpret_cast<const sockaddr_in*>(addr);
  return IpAddress::ipv4_from_network_order(v4->sin_addr.s_addr);
}

}  // namespace posix
}  // namespace net
}  // namespace traceroute
