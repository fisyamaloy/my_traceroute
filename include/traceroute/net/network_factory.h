#pragma once

#include <memory>

#include "traceroute/net/i_network_factory.h"

namespace traceroute {
namespace net {

// Should be implemented in src/platform/<os>/
std::unique_ptr<INetworkFactory> make_network_factory();

}  // namespace net
}  // namespace traceroute
