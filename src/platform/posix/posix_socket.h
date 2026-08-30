#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <chrono>

#include "platform/posix/unique_fd.h"
#include "traceroute/net/ip_address.h"

namespace traceroute {
namespace net {
namespace posix {

[[noreturn]] void throw_errno(const char* what);
[[noreturn]] void throw_send_error();

// recvfrom errors that are not fatal: keep waiting until the probe deadline.
[[nodiscard]] bool is_transient_recv_errno(int err) noexcept;

int poll_timeout_ms(std::chrono::milliseconds timeout) noexcept;
void set_fd_cloexec(int fd) noexcept;
void clear_socket_error(int fd) noexcept;
void bind_icmp_ipv4_any(int fd);
int socket_inet(int socktype, int protocol) noexcept;
UniqueFd open_icmp_dgram_socket();
IpAddress source_from_recv(const sockaddr_in& from, socklen_t from_len);

}  // namespace posix
}  // namespace net
}  // namespace traceroute
