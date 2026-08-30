#include "posix_resolver.h"

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <memory>
#include <stdexcept>
#include <string>

#include "posix_sockaddr.h"
#include "traceroute/net/address_family.h"

namespace traceroute {
namespace net {
namespace posix {
namespace {

IpAddress first_ipv4(addrinfo* result, const std::string& host) {
  std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> guard(result,
                                                             &::freeaddrinfo);
  for (const addrinfo* ai = guard.get(); ai != nullptr; ai = ai->ai_next) {
    if (ai->ai_addr != nullptr && ai->ai_family == AF_INET) {
      return from_sockaddr(ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen));
    }
  }
  throw std::runtime_error(std::string("failed to resolve host '") + host +
                           "' as IPv4");
}

}  // namespace

IpAddress PosixResolver::resolve(const std::string& host,
                                 AddressFamily family) const {
  if (family == AddressFamily::kIpv6) {
    throw std::runtime_error(kIpv6NotImplemented);
  }

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICHOST;
  addrinfo* result = nullptr;
  if (::getaddrinfo(host.c_str(), nullptr, &hints, &result) == 0) {
    return first_ipv4(result, host);
  }

  hints.ai_flags = 0;
  result = nullptr;
  const int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &result);
  if (rc != 0) {
    throw std::runtime_error(std::string("failed to resolve host '") + host +
                             "' as IPv4: " + ::gai_strerror(rc));
  }
  return first_ipv4(result, host);
}

}  // namespace posix
}  // namespace net
}  // namespace traceroute
