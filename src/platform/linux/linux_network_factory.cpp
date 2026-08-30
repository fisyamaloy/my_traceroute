#include "platform/linux/linux_network_factory.h"

#include <stdexcept>

#include "platform/linux/linux_icmp_channel.h"
#include "platform/posix/posix_resolver.h"
#include "traceroute/net/network_factory.h"
#include "traceroute/net/probe_spec.h"

namespace traceroute {
namespace net {
namespace os_linux {

std::unique_ptr<IResolver> LinuxNetworkFactory::create_resolver() const {
  return std::make_unique<posix::PosixResolver>();
}

std::unique_ptr<IProbeChannel> LinuxNetworkFactory::create_probe_channel(
    const ProbeSpec& spec, const log::Logger& log) const {
  if (const char* why = unimplemented_reason(spec)) {
    throw std::runtime_error(why);
  }
  return std::make_unique<LinuxIcmpChannel>(log);
}

}  // namespace os_linux

std::unique_ptr<INetworkFactory> make_network_factory() {
  return std::make_unique<os_linux::LinuxNetworkFactory>();
}

}  // namespace net
}  // namespace traceroute
