#pragma once

#include <memory>

#include "traceroute/log/logger.h"
#include "traceroute/net/i_probe_channel.h"
#include "traceroute/net/i_resolver.h"
#include "traceroute/net/probe_spec.h"

namespace traceroute {
namespace net {

class INetworkFactory {
 public:
  virtual ~INetworkFactory() noexcept = default;

  INetworkFactory(const INetworkFactory&) = delete;
  INetworkFactory& operator=(const INetworkFactory&) = delete;
  INetworkFactory(INetworkFactory&&) = delete;
  INetworkFactory& operator=(INetworkFactory&&) = delete;

  virtual std::unique_ptr<IResolver> create_resolver() const = 0;
  virtual std::unique_ptr<IProbeChannel> create_probe_channel(
      const ProbeSpec& spec, const log::Logger& log) const = 0;

 protected:
  INetworkFactory() noexcept = default;
};

}  // namespace net
}  // namespace traceroute
