#include "platform/posix/posix_icmp_channel.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <format>
#include <span>
#include <stdexcept>
#include <thread>

#include "platform/posix/posix_sockaddr.h"
#include "platform/posix/posix_socket.h"
#include "traceroute/net/hop_limit.h"
#include "traceroute/packet/icmpv4.h"

namespace traceroute {
namespace net {
namespace posix {

PosixIcmpChannel::PosixIcmpChannel(log::Logger log, UniqueFd fd,
                                   std::uint16_t ident,
                                   bool refresh_ident_after_send)
    : fd_(std::move(fd)),
      log_(std::move(log)),
      ident_(ident),
      refresh_ident_after_send_(refresh_ident_after_send) {
  set_fd_cloexec(fd_.get());
  bind_icmp_ipv4_any(fd_.get());
  if (ident_ == 0) {
    refresh_identifier();
  }
}

void PosixIcmpChannel::refresh_identifier() {
  sockaddr_in name{};
  socklen_t name_len = sizeof(name);
  if (::getsockname(fd_.get(), reinterpret_cast<sockaddr*>(&name), &name_len) !=
      0) {
    throw_errno("getsockname() failed");
  }
  if (name_len < static_cast<socklen_t>(sizeof(sockaddr_in)) ||
      name.sin_family != AF_INET) {
    throw std::runtime_error("getsockname() did not return an IPv4 address");
  }
  ident_ = ntohs(name.sin_port);
}

void PosixIcmpChannel::set_hop_limit(int ttl) {
  if (ttl < kMinHopLimit || ttl > kMaxHopLimit) {
    throw std::invalid_argument(std::format("hop limit must be in range {}..{}",
                                            kMinHopLimit, kMaxHopLimit));
  }
  if (::setsockopt(fd_.get(), IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
    throw_errno("setsockopt(IP_TTL) failed");
  }
  hop_limit_ = ttl;
}

std::uint16_t PosixIcmpChannel::send_probe(const IpAddress& dest,
                                           std::uint16_t seq,
                                           ByteSpan payload) {
  if (!dest.is_ipv4()) {
    throw std::logic_error(
        "IPv4 ICMP channel cannot send to a non-IPv4 address");
  }
  // Put the socket port into the packet when we already know it. Ping sockets
  // still overwrite ICMP id with that port on the wire.
  if (ident_ == 0) {
    refresh_identifier();
  }
  const SockAddr peer = to_sockaddr(dest);
  const auto packet = packet::build_echo_request(ident_, seq, payload);
  const ssize_t sent = ::sendto(fd_.get(), packet.data(), packet.size(), 0,
                                peer.as_sockaddr(), peer.length);
  if (sent < 0) {
    throw_send_error();
  }
  if (refresh_ident_after_send_) {
    // Kernel ident is what Echo Reply and quoted Time Exceeded carry.
    // Returning the pre-send userspace id breaks matching on dgram sockets
    // when the port is assigned on the first send.
    refresh_identifier();
  }
  if (log_.enabled(log::Level::kDebug)) {
    log_.log(
        log::Level::kDebug,
        std::format("send dest={} ttl={} ident={} seq={} size={}",
                    dest.to_string(), hop_limit_, ident_, seq, packet.size()));
  }
  return ident_;
}

short PosixIcmpChannel::wait_events() const noexcept {
  // POLLERR is reported even if omitted from events. Listed here so Darwin
  // EHOSTUNREACH and Linux IP_RECVERR share the same consume() path as POLLIN.
  return static_cast<short>(POLLIN | POLLERR);
}

std::optional<ReceivedPacket> PosixIcmpChannel::consume(short revents) {
  if ((revents & POLLIN) != 0) {
    if (auto pkt = recv_datagram()) {
      return pkt;
    }
  }
  if ((revents & (POLLERR | POLLHUP)) != 0) {
    clear_socket_error(fd_.get());
  }
  return std::nullopt;
}

std::optional<ReceivedPacket> PosixIcmpChannel::recv_datagram() {
  std::uint8_t buf[kRecvBufBytes];
  sockaddr_in from{};
  socklen_t from_len = sizeof(from);
  const ssize_t n = ::recvfrom(fd_.get(), buf, sizeof(buf), 0,
                               reinterpret_cast<sockaddr*>(&from), &from_len);
  if (n < 0) {
    if (is_transient_recv_errno(errno)) {
      return std::nullopt;
    }
    throw_errno("recvfrom() failed");
  }
  if (n == 0) {
    return std::nullopt;
  }

  ReceivedPacket packet;
  packet.source = source_from_recv(from, from_len);
  packet.bytes.assign(buf, buf + static_cast<std::size_t>(n));
  if (log_.enabled(log::Level::kDebug)) {
    log_.log(
        log::Level::kDebug,
        std::format("recv n={} from={} hex={}", n, packet.source.to_string(),
                    log::hex_dump(std::span<const std::uint8_t>{
                        buf, static_cast<std::size_t>(n)})));
  }
  return packet;
}

std::optional<ReceivedPacket> PosixIcmpChannel::receive(
    std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;

  while (true) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      return std::nullopt;
    }
    const auto left =
        std::chrono::ceil<std::chrono::milliseconds>(deadline - now);

    pollfd pfd{};
    pfd.fd = fd_.get();
    pfd.events = wait_events();

    const int ready = ::poll(&pfd, 1, poll_timeout_ms(left));
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw_errno("poll() failed");
    }
    if (ready == 0) {
      return std::nullopt;
    }
    if ((pfd.revents & POLLNVAL) != 0) {
      throw std::runtime_error("poll() reported an invalid fd");
    }
    if (auto pkt = consume(pfd.revents)) {
      return pkt;
    }
    // Transient: EHOSTUNREACH / empty errqueue / EAGAIN. Not a probe timeout.
    // POLLERR is level-triggered — yield so a stuck error does not spin 100%
    // CPU, then keep waiting until the deadline.
    if ((pfd.revents & (POLLERR | POLLHUP)) != 0 &&
        (pfd.revents & POLLIN) == 0) {
      const auto remaining = deadline - std::chrono::steady_clock::now();
      if (remaining <= std::chrono::steady_clock::duration::zero()) {
        return std::nullopt;
      }
      const auto yield = std::min(
          std::chrono::duration_cast<std::chrono::milliseconds>(remaining),
          std::chrono::milliseconds(1));
      if (yield.count() > 0) {
        std::this_thread::sleep_for(yield);
      }
    }
  }
}

}  // namespace posix
}  // namespace net
}  // namespace traceroute
