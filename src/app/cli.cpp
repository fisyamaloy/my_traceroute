#include "cli.h"

#include <charconv>
#include <chrono>
#include <format>
#include <ostream>
#include <stdexcept>
#include <string>
#include <system_error>

#include "traceroute/log/logger.h"
#include "traceroute/net/probe_spec.h"

namespace traceroute {
namespace app {
namespace {

int parse_positive_int(const std::string& name, const std::string& value,
                       int min_value, int max_value) {
  int parsed = 0;
  const char* const begin = value.data();
  const char* const end = value.data() + value.size();
  const auto [ptr, ec] = std::from_chars(begin, end, parsed);
  if (ec != std::errc{} || ptr != end) {
    throw std::invalid_argument(
        std::format("invalid value for {}: {}", name, value));
  }
  if (parsed < min_value || parsed > max_value) {
    throw std::invalid_argument(
        std::format("{} must be in range {}..{}", name, min_value, max_value));
  }
  return parsed;
}

const char* require_value(int argc, char* const* argv, int i,
                          const char* const name) {
  if (i + 1 >= argc) {
    throw std::invalid_argument(std::format("{} requires a value", name));
  }
  return argv[i + 1];
}

[[noreturn]] void throw_unimplemented(const net::ProbeSpec& spec) {
  const char* const why = net::unimplemented_reason(spec);
  throw std::invalid_argument(why != nullptr ? why : "not implemented");
}

}  // namespace

void print_help(std::ostream& out) {
  out << "Usage: traceroute [options] host\n"
      << "\n"
      << "Options:\n"
      << "  -h, --help         Show this help\n"
      << "  -4                 IPv4 (default)\n"
      << "  -6                 IPv6 (not implemented yet)\n"
      << "  -I                 ICMP Echo probes (default)\n"
      << "  -U                 UDP probes (not implemented yet)\n"
      << "  -m <max_ttl>       Max hops (default "
      << core::Options::kDefaultMaxTtl << ")\n"
      << "  -q <nprobes>       Probes per hop (default "
      << core::Options::kDefaultProbesPerHop << ")\n"
      << "  -w <seconds>       Per-probe timeout in seconds (default "
      << core::Options::kDefaultTimeoutSec << ")\n"
      << "  -v                 Verbose logs on stderr (info)\n"
      << "  -vv                Debug logs on stderr (hex dumps)\n";
}

CliResult parse_cli(const int argc, char* const* argv) {
  CliResult result;
  std::string host;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") {
      result.help = true;
      return result;
    }
    if (arg == "-4") {
      result.options.probe.family = net::AddressFamily::kIpv4;
      continue;
    }
    if (arg == "-6") {
      net::ProbeSpec spec;
      spec.family = net::AddressFamily::kIpv6;
      throw_unimplemented(spec);
    }
    if (arg == "-I") {
      result.options.probe.protocol = net::ProbeProtocol::kIcmpEcho;
      continue;
    }
    if (arg == "-U") {
      net::ProbeSpec spec;
      spec.protocol = net::ProbeProtocol::kUdp;
      throw_unimplemented(spec);
    }
    if (arg == "-m") {
      result.options.max_ttl =
          parse_positive_int("-m", require_value(argc, argv, i, "-m"),
                             core::Options::kMinTtl, core::Options::kMaxTtl);
      ++i;
      continue;
    }
    if (arg == "-q") {
      result.options.probes_per_hop = parse_positive_int(
          "-q", require_value(argc, argv, i, "-q"),
          core::Options::kMinProbesPerHop, core::Options::kMaxProbesPerHop);
      ++i;
      continue;
    }
    if (arg == "-w") {
      const int seconds = parse_positive_int(
          "-w", require_value(argc, argv, i, "-w"),
          core::Options::kMinTimeoutSec, core::Options::kMaxTimeoutSec);
      result.options.timeout = std::chrono::seconds(seconds);
      ++i;
      continue;
    }
    if (arg == "-vv") {
      result.options.log_level = log::Level::kDebug;
      continue;
    }
    if (arg == "-v") {
      log::bump_verbose(result.options.log_level);
      continue;
    }
    if (arg.starts_with('-')) {
      throw std::invalid_argument(std::format("unknown option: {}", arg));
    }
    if (!host.empty()) {
      throw std::invalid_argument(
          std::format("unexpected extra argument: {}", arg));
    }
    host = arg;
  }

  if (host.empty()) {
    throw std::invalid_argument("host is required");
  }
  if (host.find(':') != std::string::npos) {
    net::ProbeSpec spec;
    spec.family = net::AddressFamily::kIpv6;
    throw_unimplemented(spec);
  }
  result.options.host = host;
  return result;
}

}  // namespace app
}  // namespace traceroute
