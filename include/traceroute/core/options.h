#pragma once

#include <chrono>
#include <string>

#include "traceroute/log/logger.h"
#include "traceroute/net/hop_limit.h"
#include "traceroute/net/probe_spec.h"

namespace traceroute {
namespace core {

struct Options {
  std::string host;
  static constexpr int kDefaultMaxTtl = 30;
  static constexpr int kDefaultProbesPerHop = 3;
  static constexpr int kDefaultTimeoutSec = 4;
  static constexpr int kMinProbesPerHop = 1;
  static constexpr int kMaxProbesPerHop = 10;
  static constexpr int kMinTtl = net::kMinHopLimit;
  static constexpr int kMaxTtl = net::kMaxHopLimit;
  static constexpr int kMinTimeoutSec = 1;
  static constexpr int kMaxTimeoutSec = 60;
  int max_ttl = kDefaultMaxTtl;
  int probes_per_hop = kDefaultProbesPerHop;
  std::chrono::milliseconds timeout{kDefaultTimeoutSec * 1000};
  net::ProbeSpec probe;
  log::Level log_level = log::Level::kWarn;
};

}  // namespace core
}  // namespace traceroute
