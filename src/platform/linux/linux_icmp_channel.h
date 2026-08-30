#pragma once

#include <optional>

#include "platform/posix/posix_icmp_channel.h"
#include "platform/posix/unique_fd.h"
#include "traceroute/net/received_packet.h"

namespace traceroute {
namespace net {
namespace os_linux {

class LinuxIcmpChannel final : public posix::PosixIcmpChannel {
 public:
  explicit LinuxIcmpChannel(log::Logger log = {});

 protected:
  [[nodiscard]] std::optional<ReceivedPacket> consume(short revents) override;

 private:
  struct Opened {
    posix::UniqueFd fd;
    std::uint16_t ident = 0;
    bool refresh_after_send = true;
  };

  struct ErrqueueRead {
    std::optional<ReceivedPacket> packet;
    bool idle = false;
  };

  static Opened open_socket();
  explicit LinuxIcmpChannel(log::Logger log, Opened opened);

  [[nodiscard]] ErrqueueRead recv_errqueue();
};

}  // namespace os_linux
}  // namespace net
}  // namespace traceroute
