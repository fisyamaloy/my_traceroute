#include "posix_network_factory.h"

#include <stdexcept>

#include "platform/posix/posix_icmp_dgram_channel.h"
#include "platform/posix/posix_resolver.h"
#include "traceroute/net/network_factory.h"
#include "traceroute/net/probe_spec.h"

namespace traceroute {
namespace net {
namespace posix {

std::unique_ptr<IResolver> PosixNetworkFactory::create_resolver() const {
  return std::make_unique<PosixResolver>();
}

std::unique_ptr<IProbeChannel> PosixNetworkFactory::create_probe_channel(
    const ProbeSpec& spec, const log::Logger& log) const {
  if (const char* why = unimplemented_reason(spec)) {
    throw std::runtime_error(why);
  }
  return std::make_unique<PosixIcmpDgramChannel>(log);
}

}  // namespace posix

std::unique_ptr<INetworkFactory> make_network_factory() {
  return std::make_unique<posix::PosixNetworkFactory>();
}

}  // namespace net
}  // namespace traceroute
