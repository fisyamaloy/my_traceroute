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

[[nodiscard]] int poll_timeout_ms(std::chrono::milliseconds timeout) noexcept;
void set_fd_cloexec(int fd) noexcept;
void clear_socket_error(int fd) noexcept;
void bind_icmp_ipv4_any(int fd);
[[nodiscard]] int socket_inet(int socktype, int protocol) noexcept;
[[nodiscard]] UniqueFd open_icmp_dgram_socket();
[[nodiscard]] IpAddress source_from_recv(const sockaddr_in& from,
                                         socklen_t from_len) noexcept;

}  // namespace posix
}  // namespace net
}  // namespace traceroute
