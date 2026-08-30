#include "platform/linux/linux_icmp_channel.h"

#include <linux/errqueue.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <format>
#include <optional>
#include <utility>

#include "platform/posix/posix_sockaddr.h"
#include "platform/posix/posix_socket.h"
#include "traceroute/net/ip_address.h"
#include "traceroute/packet/icmpv4.h"

namespace traceroute {
namespace net {
namespace os_linux {
namespace {

using posix::clear_socket_error;
using posix::socket_inet;
using posix::throw_errno;

}  // namespace

LinuxIcmpChannel::Opened LinuxIcmpChannel::open_socket() {
  Opened opened;

  const int raw_fd = socket_inet(SOCK_RAW, IPPROTO_ICMP);
  if (raw_fd >= 0) {
    opened.fd = posix::UniqueFd(raw_fd);
    opened.ident = static_cast<std::uint16_t>(::getpid());
    if (opened.ident == 0) {
      opened.ident = 1;
    }
    opened.refresh_after_send = false;
    return opened;
  }

  const int dgram_fd = socket_inet(SOCK_DGRAM, IPPROTO_ICMP);
  if (dgram_fd < 0) {
    throw_errno(
        "socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) failed; on Linux enable "
        "unprivileged ICMP: sysctl net.ipv4.ping_group_range='0 2147483647'");
  }
  opened.fd = posix::UniqueFd(dgram_fd);
  const int on = 1;
  if (::setsockopt(opened.fd.get(), SOL_IP, IP_RECVERR, &on, sizeof(on)) != 0) {
    throw_errno("setsockopt(IP_RECVERR) failed");
  }
  opened.ident = 0;
  opened.refresh_after_send = true;
  return opened;
}

LinuxIcmpChannel::LinuxIcmpChannel(log::Logger log)
    : LinuxIcmpChannel(std::move(log), open_socket()) {}

LinuxIcmpChannel::LinuxIcmpChannel(log::Logger log, Opened opened)
    : posix::PosixIcmpChannel(std::move(log), std::move(opened.fd),
                              opened.ident, opened.refresh_after_send) {
  if (log_.enabled(log::Level::kInfo)) {
    log_.log(log::Level::kInfo,
             std::format("icmp linux fd={} ident={} refresh_after_send={}",
                         fd_.get(), ident_, refresh_ident_after_send_));
  }
}

LinuxIcmpChannel::ErrqueueRead LinuxIcmpChannel::recv_errqueue() {
  ErrqueueRead out;
  alignas(cmsghdr) char
      cbuf[CMSG_SPACE(sizeof(sock_extended_err) + sizeof(sockaddr_in))];
  std::uint8_t data[kRecvBufBytes];
  sockaddr_in name{};
  iovec iov{};
  iov.iov_base = data;
  iov.iov_len = sizeof(data);
  msghdr msg{};
  msg.msg_name = &name;
  msg.msg_namelen = sizeof(name);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);

  const ssize_t n = ::recvmsg(fd_.get(), &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
      out.idle = true;
      return out;
    }
    throw_errno("recvmsg(MSG_ERRQUEUE) failed");
  }

  const sock_extended_err* err = nullptr;
  for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
      err = reinterpret_cast<const sock_extended_err*>(CMSG_DATA(cmsg));
      break;
    }
  }
  if (err == nullptr || err->ee_origin != SO_EE_ORIGIN_ICMP) {
    return out;
  }

  ReceivedPacket packet;
  const auto* offender = reinterpret_cast<const sockaddr*>(SO_EE_OFFENDER(err));
  if (offender != nullptr && offender->sa_family == AF_INET) {
    packet.source = posix::from_sockaddr(offender, sizeof(sockaddr_in));
  } else {
    // msg_name is the original destination, not the hop. Leave unspecified
    // so the engine prints "???" instead of the target IP as an intermediate.
    packet.source = IpAddress{};
  }
  packet.bytes = packet::wrap_quoted_as_icmp_error(
      err->ee_type, err->ee_code, ByteSpan{data, static_cast<std::size_t>(n)});
  if (log_.enabled(log::Level::kDebug)) {
    log_.log(log::Level::kDebug,
             std::format("errqueue type={} code={} from={} n={}", err->ee_type,
                         err->ee_code, packet.source.to_string(), n));
  }
  out.packet = std::move(packet);
  return out;
}

std::optional<ReceivedPacket> LinuxIcmpChannel::consume(short revents) {
  if ((revents & POLLERR) != 0) {
    for (int n = 0; n < 64; ++n) {
      const ErrqueueRead read = recv_errqueue();
      if (read.packet) {
        return read.packet;
      }
      if (read.idle) {
        break;
      }
    }
    clear_socket_error(fd_.get());
  }
  if ((revents & POLLIN) != 0) {
    if (auto pkt = recv_datagram()) {
      return pkt;
    }
    const ErrqueueRead read = recv_errqueue();
    if (read.packet) {
      return read.packet;
    }
  }
  return std::nullopt;
}

}  // namespace os_linux
}  // namespace net
}  // namespace traceroute
