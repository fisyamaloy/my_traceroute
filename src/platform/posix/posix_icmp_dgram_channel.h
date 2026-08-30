#pragma once

#include "platform/posix/posix_icmp_channel.h"

namespace traceroute {
namespace net {
namespace posix {

class PosixIcmpDgramChannel final : public PosixIcmpChannel {
 public:
  explicit PosixIcmpDgramChannel(log::Logger log = {});
};

}  // namespace posix
}  // namespace net
}  // namespace traceroute
