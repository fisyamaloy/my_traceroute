#include "traceroute/core/engine.h"

#include <catch_amalgamated.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "packet_fixtures.h"
#include "traceroute/core/options.h"
#include "traceroute/log/logger.h"
#include "traceroute/net/address_family.h"
#include "traceroute/net/i_network_factory.h"
#include "traceroute/net/i_probe_channel.h"
#include "traceroute/net/i_resolver.h"
#include "traceroute/net/ip_address.h"
#include "traceroute/net/received_packet.h"
#include "traceroute/packet/icmpv4.h"

using traceroute::core::Options;
using traceroute::log::Logger;
using traceroute::net::AddressFamily;
using traceroute::net::ByteSpan;
using traceroute::net::INetworkFactory;
using traceroute::net::IpAddress;
using traceroute::net::IProbeChannel;
using traceroute::net::IResolver;
using traceroute::net::ProbeSpec;
using traceroute::net::ReceivedPacket;
using traceroute::packet::build_echo_request;
using traceroute::packet::Icmpv4TimeExceededCode;
using traceroute::packet::Icmpv4Type;
using traceroute::packet::Icmpv4UnreachCode;
using traceroute::packet::ProbeReplyKind;
using traceroute::test::as_echo_reply;
using traceroute::test::icmp_error;
using traceroute::test::ipv4;
using traceroute::test::packet_from;
using traceroute::test::wrap_ipv4;

namespace {

class FakeResolver : public IResolver {
 public:
  explicit FakeResolver(IpAddress addr) : addr_(addr) {}

  IpAddress resolve(const std::string&, AddressFamily) const override {
    return addr_;
  }

 private:
  IpAddress addr_;
};

class ScriptedChannel : public IProbeChannel {
 public:
  ScriptedChannel(std::uint16_t ident,
                  std::vector<std::optional<ReceivedPacket>> replies)
      : ident_(ident), replies_(std::move(replies)) {}

  void set_hop_limit(int) override {}

  std::uint16_t send_probe(const IpAddress&, std::uint16_t, ByteSpan) override {
    return ident_;
  }

  std::optional<ReceivedPacket> receive(std::chrono::milliseconds) override {
    if (next_ >= replies_.size()) {
      return std::nullopt;
    }
    return replies_[next_++];
  }

 private:
  std::uint16_t ident_;
  std::vector<std::optional<ReceivedPacket>> replies_;
  std::size_t next_ = 0;
};

class ScriptedFactory : public INetworkFactory {
 public:
  ScriptedFactory(IpAddress dest, std::uint16_t ident,
                  std::vector<std::optional<ReceivedPacket>> replies)
      : dest_(dest), ident_(ident), replies_(std::move(replies)) {}

  std::unique_ptr<IResolver> create_resolver() const override {
    return std::make_unique<FakeResolver>(dest_);
  }

  std::unique_ptr<IProbeChannel> create_probe_channel(
      const ProbeSpec&, const Logger&) const override {
    return std::make_unique<ScriptedChannel>(ident_, replies_);
  }

 private:
  IpAddress dest_;
  std::uint16_t ident_;
  std::vector<std::optional<ReceivedPacket>> replies_;
};

Options test_options() {
  Options options;
  options.host = "example.com";
  options.max_ttl = 3;
  options.probes_per_hop = 1;
  options.timeout = std::chrono::milliseconds(20);
  return options;
}

}  // namespace

TEST_CASE("engine stops on echo reply") {
  const auto dest = ipv4(8, 8, 8, 8);
  constexpr std::uint16_t kIdent = 0x1234;
  auto echo = as_echo_reply(build_echo_request(kIdent, 1, {}));
  ScriptedFactory factory(dest, kIdent, {packet_from(dest, std::move(echo))});

  std::ostringstream out;
  const int rc = traceroute::core::run(factory, test_options(), out, Logger{});
  REQUIRE(rc == 0);
  REQUIRE(out.str().find("8.8.8.8") != std::string::npos);
  REQUIRE(out.str().find('*') == std::string::npos);
}

TEST_CASE("engine prints stars on timeout") {
  const auto dest = ipv4(1, 1, 1, 1);
  ScriptedFactory factory(dest, 1, {});
  auto options = test_options();
  options.max_ttl = 2;

  std::ostringstream out;
  const int rc = traceroute::core::run(factory, options, out, Logger{});
  REQUIRE(rc == 1);
  REQUIRE(out.str().find('*') != std::string::npos);
}

TEST_CASE("engine walks hops then stops") {
  const auto dest = ipv4(8, 8, 4, 4);
  const auto hop = ipv4(10, 0, 0, 1);
  const auto us = ipv4(192, 168, 0, 2);
  constexpr std::uint16_t kIdent = 0xBEEF;

  const auto inner = wrap_ipv4(us, dest, build_echo_request(kIdent, 1, {}));
  const auto te = icmp_error(
      Icmpv4Type::kTimeExceeded,
      static_cast<std::uint8_t>(Icmpv4TimeExceededCode::kTtl), inner);
  auto echo = as_echo_reply(build_echo_request(kIdent, 2, {}));

  ScriptedFactory factory(dest, kIdent,
                          {packet_from(hop, wrap_ipv4(hop, us, te)),
                           packet_from(dest, std::move(echo))});

  std::ostringstream out;
  const int rc = traceroute::core::run(factory, test_options(), out, Logger{});
  REQUIRE(rc == 0);
  REQUIRE(out.str().find("10.0.0.1") != std::string::npos);
  REQUIRE(out.str().find("8.8.4.4") != std::string::npos);
}

TEST_CASE("engine skips unmatched packets until a match") {
  const auto dest = ipv4(8, 8, 8, 8);
  constexpr std::uint16_t kIdent = 9;
  auto wrong = as_echo_reply(build_echo_request(kIdent, 99, {}));
  auto echo = as_echo_reply(build_echo_request(kIdent, 1, {}));
  ScriptedFactory factory(dest, kIdent,
                          {packet_from(dest, std::move(wrong)),
                           packet_from(dest, std::move(echo))});

  std::ostringstream out;
  const int rc = traceroute::core::run(factory, test_options(), out, Logger{});
  REQUIRE(rc == 0);
}

TEST_CASE("engine stops on dest unreachable") {
  const auto dest = ipv4(8, 8, 4, 4);
  const auto hop = ipv4(10, 0, 0, 1);
  const auto us = ipv4(192, 168, 0, 2);
  constexpr std::uint16_t kIdent = 1;
  const auto inner = wrap_ipv4(us, dest, build_echo_request(kIdent, 1, {}));
  const auto unreach =
      icmp_error(Icmpv4Type::kDestUnreachable,
                 static_cast<std::uint8_t>(Icmpv4UnreachCode::kHost), inner);

  ScriptedFactory factory(dest, kIdent,
                          {packet_from(hop, wrap_ipv4(hop, us, unreach))});

  std::ostringstream out;
  auto options = test_options();
  options.max_ttl = 5;
  const int rc = traceroute::core::run(factory, options, out, Logger{});
  REQUIRE(rc == 0);
  REQUIRE(out.str().find("!H") != std::string::npos);
}

TEST_CASE("trace returns structured hops") {
  const auto dest = ipv4(8, 8, 8, 8);
  constexpr std::uint16_t kIdent = 0x1234;
  auto echo = as_echo_reply(build_echo_request(kIdent, 1, {}));
  ScriptedFactory factory(dest, kIdent, {packet_from(dest, std::move(echo))});

  const auto result =
      traceroute::core::trace(factory, test_options(), Logger{});
  REQUIRE(result.reached);
  REQUIRE(result.hops.size() == 1);
  REQUIRE(result.hops[0].ttl == 1);
  REQUIRE_FALSE(result.hops[0].probes[0].timeout);
  REQUIRE(result.hops[0].probes[0].kind == ProbeReplyKind::kEchoReply);
  REQUIRE(result.hops[0].probes[0].responder == dest);
}

TEST_CASE("engine keeps probing after a timeout on the same hop") {
  const auto dest = ipv4(8, 8, 8, 8);
  constexpr std::uint16_t kIdent = 0x1234;
  auto echo = as_echo_reply(build_echo_request(kIdent, 2, {}));
  ScriptedFactory factory(dest, kIdent,
                          {std::nullopt, packet_from(dest, std::move(echo))});

  auto options = test_options();
  options.probes_per_hop = 2;
  std::ostringstream out;
  const int rc = traceroute::core::run(factory, options, out, Logger{});
  REQUIRE(rc == 0);
  REQUIRE(out.str().find('*') != std::string::npos);
  REQUIRE(out.str().find("8.8.8.8") != std::string::npos);
}

TEST_CASE("engine prints ??? when TE has no hop address") {
  const auto dest = ipv4(8, 8, 4, 4);
  const auto us = ipv4(192, 168, 0, 2);
  constexpr std::uint16_t kIdent = 1;
  const auto inner = wrap_ipv4(us, dest, build_echo_request(kIdent, 1, {}));
  const auto te = icmp_error(
      Icmpv4Type::kTimeExceeded,
      static_cast<std::uint8_t>(Icmpv4TimeExceededCode::kTtl), inner);

  ScriptedFactory factory(dest, kIdent, {packet_from(IpAddress{}, te)});
  auto options = test_options();
  options.max_ttl = 1;

  std::ostringstream out;
  const int rc = traceroute::core::run(factory, options, out, Logger{});
  REQUIRE(rc == 1);
  REQUIRE(out.str().find("???") != std::string::npos);
  REQUIRE(out.str().find('*') == std::string::npos);
  REQUIRE(out.str().find("ms") != std::string::npos);
}

TEST_CASE("dest unreachable without hop IP still stops") {
  const auto dest = ipv4(8, 8, 4, 4);
  const auto us = ipv4(192, 168, 0, 2);
  constexpr std::uint16_t kIdent = 1;
  const auto inner = wrap_ipv4(us, dest, build_echo_request(kIdent, 1, {}));
  const auto unreach =
      icmp_error(Icmpv4Type::kDestUnreachable,
                 static_cast<std::uint8_t>(Icmpv4UnreachCode::kHost), inner);

  ScriptedFactory factory(dest, kIdent, {packet_from(IpAddress{}, unreach)});
  std::ostringstream out;
  auto options = test_options();
  options.max_ttl = 5;
  const int rc = traceroute::core::run(factory, options, out, Logger{});
  REQUIRE(rc == 0);
  REQUIRE(out.str().find("???") != std::string::npos);
  REQUIRE(out.str().find("!H") != std::string::npos);
}

TEST_CASE("destination_reached does not require a hop IP") {
  traceroute::core::TraceHop hop;
  traceroute::core::ProbeResult probe;
  probe.timeout = false;
  probe.kind = ProbeReplyKind::kDestUnreachable;
  hop.probes.push_back(probe);
  REQUIRE(traceroute::core::destination_reached(hop));
}

TEST_CASE("write_hop prints ??? once for unknown responders") {
  traceroute::core::TraceHop hop;
  hop.ttl = 3;
  traceroute::core::ProbeResult a;
  a.timeout = false;
  a.kind = ProbeReplyKind::kTimeExceeded;
  a.rtt = std::chrono::microseconds(1234);
  traceroute::core::ProbeResult b = a;
  b.rtt = std::chrono::microseconds(2345);
  hop.probes.push_back(a);
  hop.probes.push_back(b);

  std::ostringstream out;
  traceroute::core::write_hop(out, hop, ProbeSpec{});
  const std::string text = out.str();
  REQUIRE(text.find("???") != std::string::npos);
  REQUIRE(text.find('*') == std::string::npos);
  REQUIRE(text.find("1.234 ms") != std::string::npos);
  REQUIRE(text.find("2.345 ms") != std::string::npos);
  REQUIRE(text.find("???") == text.rfind("???"));
}
