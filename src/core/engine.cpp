#include "traceroute/core/engine.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <iomanip>
#include <ios>
#include <optional>
#include <ostream>
#include <utility>
#include <vector>

#include "traceroute/log/logger.h"
#include "traceroute/packet/icmpv4.h"
#include "traceroute/packet/probe_reply.h"

namespace traceroute {
namespace core {
namespace {

using clock = std::chrono::steady_clock;

constexpr std::uint16_t kFirstProbeSeq = 1;
constexpr const char* kUnknownResponder = "???";

struct TimedReply {
  packet::ProbeReply reply;
  clock::time_point received_at;
};

std::optional<TimedReply> wait_for_reply(net::IProbeChannel& channel,
                                         const net::ProbeSpec& spec,
                                         std::uint16_t id, std::uint16_t seq,
                                         std::chrono::milliseconds timeout,
                                         const log::Logger& log) {
  const auto deadline = clock::now() + timeout;
  while (true) {
    const auto now = clock::now();
    if (now >= deadline) {
      return std::nullopt;
    }
    const auto left =
        std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
    if (left.count() <= 0) {
      return std::nullopt;
    }
    const auto raw = channel.receive(left);
    const auto received_at = clock::now();
    if (!raw) {
      return std::nullopt;
    }
    const auto matched =
        packet::match_probe_reply(spec, raw->bytes, raw->source, id, seq);
    if (matched) {
      return TimedReply{*matched, received_at};
    }
    if (log.enabled(log::Level::kDebug)) {
      log.log(log::Level::kDebug,
              std::format("unmatched packet from {} hex={}",
                          raw->source.to_string(), log::hex_dump(raw->bytes)));
    }
  }
}

class StreamFormat {
 public:
  explicit StreamFormat(std::ostream& out)
      : out_(out), flags_(out.flags()), precision_(out.precision()) {}
  ~StreamFormat() {
    out_.flags(flags_);
    out_.precision(precision_);
  }
  StreamFormat(const StreamFormat&) = delete;
  StreamFormat& operator=(const StreamFormat&) = delete;
  StreamFormat(StreamFormat&&) = delete;
  StreamFormat& operator=(StreamFormat&&) = delete;

 private:
  std::ostream& out_;
  std::ios::fmtflags flags_;
  std::streamsize precision_;
};

void print_rtt(std::ostream& out, std::chrono::microseconds rtt,
               const char* suffix) {
  const StreamFormat restore(out);
  out << std::fixed << std::setprecision(3)
      << (static_cast<double>(rtt.count()) / 1000.0) << " ms" << suffix;
}

TraceHop probe_ttl(net::IProbeChannel& channel, const net::IpAddress& dest,
                   const net::ProbeSpec& spec, int ttl, std::uint16_t& seq,
                   const Options& options, const log::Logger& log) {
  TraceHop hop;
  hop.ttl = ttl;
  hop.probes.reserve(static_cast<std::size_t>(options.probes_per_hop));
  channel.set_hop_limit(ttl);

  const std::vector<std::uint8_t> payload(packet::kEchoPayloadBytes, 0);

  for (int probe = 0; probe < options.probes_per_hop; ++probe) {
    ProbeResult sample;
    const auto sent_at = clock::now();
    const std::uint16_t ident = channel.send_probe(dest, seq, payload);
    const auto reply =
        wait_for_reply(channel, spec, ident, seq, options.timeout, log);
    ++seq;

    if (!reply) {
      hop.probes.push_back(sample);
      continue;
    }

    net::IpAddress responder = reply->reply.responder;
    if (responder.is_unspecified() &&
        reply->reply.kind == packet::ProbeReplyKind::kEchoReply) {
      responder = dest;
    }

    sample.timeout = false;
    if (!responder.is_unspecified()) {
      sample.responder = responder;
    }
    sample.kind = reply->reply.kind;
    sample.code = reply->reply.code;
    sample.rtt = std::chrono::duration_cast<std::chrono::microseconds>(
        reply->received_at - sent_at);
    hop.probes.push_back(sample);
  }
  return hop;
}

}  // namespace

bool destination_reached(const TraceHop& hop) noexcept {
  for (const ProbeResult& probe : hop.probes) {
    if (probe.timeout) {
      continue;
    }
    if (probe.kind == packet::ProbeReplyKind::kEchoReply ||
        probe.kind == packet::ProbeReplyKind::kDestUnreachable) {
      return true;
    }
  }
  return false;
}

TraceResult trace(const net::INetworkFactory& factory, const Options& options,
                  const log::Logger& log, std::ostream* out) {
  auto resolver = factory.create_resolver();
  TraceResult result;
  result.host = options.host;
  result.dest = resolver->resolve(options.host, options.probe.family);
  result.max_ttl = options.max_ttl;
  result.probe = options.probe;
  result.probe.family = result.dest.family();

  if (log.enabled(log::Level::kInfo)) {
    log.log(log::Level::kInfo, std::format("resolved {} -> {}", options.host,
                                           result.dest.to_string()));
  }

  auto channel = factory.create_probe_channel(result.probe, log);
  if (out != nullptr) {
    write_banner(*out, result);
  }

  std::uint16_t seq = kFirstProbeSeq;
  for (int ttl = 1; ttl <= options.max_ttl; ++ttl) {
    TraceHop hop =
        probe_ttl(*channel, result.dest, result.probe, ttl, seq, options, log);
    const bool reached = destination_reached(hop);
    result.hops.push_back(std::move(hop));
    if (reached) {
      result.reached = true;
    }
    if (out != nullptr) {
      write_hop(*out, result.hops.back(), result.probe);
    }
    if (result.reached) {
      break;
    }
  }
  return result;
}

void write_banner(std::ostream& out, const TraceResult& result) {
  out << "traceroute to " << result.host << " (" << result.dest.to_string()
      << "), " << result.max_ttl << " hops max\n"
      << std::flush;
}

void write_hop(std::ostream& out, const TraceHop& hop,
               const net::ProbeSpec& spec) {
  {
    const StreamFormat restore(out);
    out << std::setw(2) << hop.ttl << "  " << std::flush;
  }
  std::optional<net::IpAddress> last_printed;
  bool last_unknown = false;
  for (std::size_t i = 0; i < hop.probes.size(); ++i) {
    if (i != 0) {
      out << "  ";
    }
    const ProbeResult& probe = hop.probes[i];
    if (probe.timeout) {
      out << "*";
      last_printed.reset();
      last_unknown = false;
      continue;
    }
    if (!probe.responder) {
      if (!last_unknown) {
        out << kUnknownResponder << "  ";
        last_unknown = true;
        last_printed.reset();
      }
    } else if (!last_printed || *last_printed != *probe.responder) {
      out << probe.responder->to_string() << "  ";
      last_printed = *probe.responder;
      last_unknown = false;
    }
    const char* tag = "";
    if (probe.kind == packet::ProbeReplyKind::kDestUnreachable) {
      tag = packet::unreach_tag(spec, probe.code);
    }
    print_rtt(out, probe.rtt, tag);
  }
  out << '\n' << std::flush;
}

int run(const net::INetworkFactory& factory, const Options& options,
        std::ostream& out, const log::Logger& log) {
  return trace(factory, options, log, &out).reached ? 0 : 1;
}

}  // namespace core
}  // namespace traceroute
