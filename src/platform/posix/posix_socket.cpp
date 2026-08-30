#include "platform/posix/posix_socket.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cerrno>
#include <limits>
#include <stdexcept>
#include <system_error>

#include "platform/posix/posix_sockaddr.h"

namespace traceroute {
namespace net {
namespace posix {

void throw_errno(const char* what) {
  throw std::system_error(errno, std::generic_category(), what);
}

void throw_send_error() {
  if (errno == EHOSTUNREACH || errno == ENETUNREACH) {
    throw std::runtime_error("no route to destination");
  }
  throw_errno("sendto() failed");
}

bool is_transient_recv_errno(int err) noexcept {
  return err == EINTR || err == EAGAIN || err == EWOULDBLOCK ||
         err == EHOSTUNREACH || err == ENETUNREACH || err == EMSGSIZE;
}

int poll_timeout_ms(std::chrono::milliseconds timeout) noexcept {
  if (timeout.count() <= 0) {
    return 0;
  }
  if (timeout.count() > std::numeric_limits<int>::max()) {
    return std::numeric_limits<int>::max();
  }
  return static_cast<int>(timeout.count());
}

void set_fd_cloexec(int fd) noexcept {
  const int flags = ::fcntl(fd, F_GETFD);
  if (flags < 0) {
    return;
  }
  (void)::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

void clear_socket_error(int fd) noexcept {
  int soerr = 0;
  socklen_t slen = sizeof(soerr);
  (void)::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
}

int socket_inet(int socktype, int protocol) noexcept {
  int fd = -1;
#if defined(SOCK_CLOEXEC)
  fd = ::socket(AF_INET, socktype | SOCK_CLOEXEC, protocol);
  if (fd >= 0) {
    return fd;
  }
#endif
  fd = ::socket(AF_INET, socktype, protocol);
  if (fd >= 0) {
    set_fd_cloexec(fd);
  }
  return fd;
}

void bind_icmp_ipv4_any(int fd) {
  sockaddr_in any{};
  any.sin_family = AF_INET;
  any.sin_addr.s_addr = htonl(INADDR_ANY);
  any.sin_port = 0;
  if (::bind(fd, reinterpret_cast<const sockaddr*>(&any), sizeof(any)) == 0) {
    return;
  }
  if (errno == EINVAL) {
    sockaddr_in name{};
    socklen_t name_len = sizeof(name);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&name), &name_len) == 0) {
      return;
    }
  }
  throw_errno("bind() on ICMP socket failed");
}

UniqueFd open_icmp_dgram_socket() {
  const int fd = socket_inet(SOCK_DGRAM, IPPROTO_ICMP);
  if (fd < 0) {
    throw_errno("socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) failed");
  }
  return UniqueFd(fd);
}

IpAddress source_from_recv(const sockaddr_in& from, socklen_t from_len) {
  if (from_len < static_cast<socklen_t>(sizeof(sockaddr_in)) ||
      from.sin_family != AF_INET) {
    return IpAddress::ipv4_from_host_order(0);
  }
  return from_sockaddr(reinterpret_cast<const sockaddr*>(&from), from_len);
}

}  // namespace posix
}  // namespace net
}  // namespace traceroute
