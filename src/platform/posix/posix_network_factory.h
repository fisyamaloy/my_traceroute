#pragma once

#include "traceroute/net/i_network_factory.h"

namespace traceroute {
namespace net {
namespace posix {

class PosixNetworkFactory : public INetworkFactory {
 public:
  std::unique_ptr<IResolver> create_resolver() const override;
  std::unique_ptr<IProbeChannel> create_probe_channel(
      const ProbeSpec& spec, const log::Logger& log) const override;
};

}  // namespace posix
}  // namespace net
}  // namespace traceroute
