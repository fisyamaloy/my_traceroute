#pragma once

#include <chrono>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

#include "traceroute/core/options.h"
#include "traceroute/log/logger.h"
#include "traceroute/net/i_network_factory.h"
#include "traceroute/net/ip_address.h"
#include "traceroute/net/probe_spec.h"
#include "traceroute/packet/probe_reply.h"

namespace traceroute {
namespace core {

struct ProbeResult {
  bool timeout = true;
  std::optional<net::IpAddress> responder;
  std::chrono::microseconds rtt{0};
  packet::ProbeReplyKind kind = packet::ProbeReplyKind::kTimeExceeded;
  std::uint8_t code = 0;
};

struct TraceHop {
  int ttl = 0;
  std::vector<ProbeResult> probes;
};

struct TraceResult {
  std::string host;
  net::IpAddress dest;
  int max_ttl = 0;
  net::ProbeSpec probe;
  std::vector<TraceHop> hops;
  bool reached = false;
};

[[nodiscard]] bool destination_reached(const TraceHop& hop) noexcept;

// Single TTL loop. If out != nullptr, prints banner/hops as they complete.
[[nodiscard]] TraceResult trace(const net::INetworkFactory& factory,
                                const Options& options, const log::Logger& log,
                                std::ostream* out = nullptr);

void write_banner(std::ostream& out, const TraceResult& result);
void write_hop(std::ostream& out, const TraceHop& hop,
               const net::ProbeSpec& spec);

// Prints as probes complete. Returns 0 if the destination answered, 1 if max
// TTL was reached.
[[nodiscard]] int run(const net::INetworkFactory& factory,
                      const Options& options, std::ostream& out,
                      const log::Logger& log);

}  // namespace core
}  // namespace traceroute
