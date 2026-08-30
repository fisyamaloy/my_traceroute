#include "platform/posix/posix_icmp_dgram_channel.h"

#include <format>
#include <utility>

#include "platform/posix/posix_socket.h"

namespace traceroute {
namespace net {
namespace posix {

PosixIcmpDgramChannel::PosixIcmpDgramChannel(log::Logger log)
    : PosixIcmpChannel(std::move(log), open_icmp_dgram_socket(),
                       /*ident=*/0, /*refresh_ident_after_send=*/true) {
  if (log_.enabled(log::Level::kInfo)) {
    log_.log(log::Level::kInfo,
             std::format("icmp dgram fd={} ident={}", fd_.get(), ident_));
  }
}

}  // namespace posix
}  // namespace net
}  // namespace traceroute
