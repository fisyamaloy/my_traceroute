#include <catch_amalgamated.hpp>
#include <cstdint>
#include <string>
#include <vector>

#include "packet_fixtures.h"
#include "traceroute/net/probe_spec.h"
#include "traceroute/packet/checksum.h"
#include "traceroute/packet/icmpv4.h"
#include "traceroute/packet/probe_reply.h"

using traceroute::net::AddressFamily;
using traceroute::net::ProbeProtocol;
using traceroute::net::ProbeSpec;
using traceroute::packet::build_echo_request;
using traceroute::packet::Icmpv4TimeExceededCode;
using traceroute::packet::Icmpv4Type;
using traceroute::packet::Icmpv4UnreachCode;
using traceroute::packet::internet_checksum;
using traceroute::packet::kIcmpChecksumOffset;
using traceroute::packet::kIcmpCodeOffset;
using traceroute::packet::kIcmpEchoCode;
using traceroute::packet::kIcmpEchoIdOffset;
using traceroute::packet::kIcmpEchoSeqOffset;
using traceroute::packet::kIcmpHeaderBytes;
using traceroute::packet::kIcmpTypeOffset;
using traceroute::packet::kIpv4MinHeaderBytes;
using traceroute::packet::match_ipv4_probe_reply;
using traceroute::packet::match_probe_reply;
using traceroute::packet::ProbeReplyKind;
using traceroute::packet::unreach_tag;
using traceroute::packet::wrap_quoted_as_icmp_error;
using traceroute::test::as_echo_reply;
using traceroute::test::icmp_error;
using traceroute::test::ipv4;
using traceroute::test::wrap_ipv4;

TEST_CASE("IpAddress IPv4 round-trip") {
  const auto addr = ipv4(8, 8, 8, 8);
  REQUIRE(addr.is_ipv4());
  REQUIRE(addr.to_string() == "8.8.8.8");
  REQUIRE(addr ==
          traceroute::net::IpAddress::ipv4_from_host_order(0x08080808u));
  REQUIRE(ipv4(0, 0, 0, 0).is_unspecified());
}

TEST_CASE("build_echo_request layout and checksum") {
  const std::uint8_t payload[] = {1, 2, 3, 4};
  const auto pkt = build_echo_request(0x1234, 0x0007, payload);
  REQUIRE(pkt.size() == kIcmpHeaderBytes + sizeof(payload));
  REQUIRE(pkt[kIcmpTypeOffset] ==
          static_cast<std::uint8_t>(Icmpv4Type::kEchoRequest));
  REQUIRE(pkt[kIcmpCodeOffset] == kIcmpEchoCode);
  REQUIRE(pkt[kIcmpEchoIdOffset] == 0x12);
  REQUIRE(pkt[kIcmpEchoIdOffset + 1] == 0x34);
  REQUIRE(pkt[kIcmpEchoSeqOffset] == 0x00);
  REQUIRE(pkt[kIcmpEchoSeqOffset + 1] == 0x07);
  REQUIRE(internet_checksum(pkt) == 0);
}

TEST_CASE("match echo reply") {
  const auto dest = ipv4(8, 8, 8, 8);
  const auto echo = as_echo_reply(build_echo_request(0x1234, 7, {}));
  const auto reply = match_ipv4_probe_reply(echo, dest, 0x1234, 7);
  REQUIRE(reply.has_value());
  REQUIRE(reply->kind == ProbeReplyKind::kEchoReply);
  REQUIRE(reply->responder == dest);
}

TEST_CASE("match time exceeded") {
  const auto hop = ipv4(10, 0, 0, 1);
  const auto dest = ipv4(8, 8, 4, 4);
  const auto us = ipv4(192, 168, 0, 2);
  const auto inner = wrap_ipv4(us, dest, build_echo_request(0xBEEF, 42, {}));
  const auto icmp = icmp_error(
      Icmpv4Type::kTimeExceeded,
      static_cast<std::uint8_t>(Icmpv4TimeExceededCode::kTtl), inner);
  const auto datagram = wrap_ipv4(hop, us, icmp);
  const auto reply = match_ipv4_probe_reply(datagram, hop, 0xBEEF, 42);
  REQUIRE(reply.has_value());
  REQUIRE(reply->kind == ProbeReplyKind::kTimeExceeded);
  REQUIRE(reply->responder == hop);
}

TEST_CASE("match dest unreachable") {
  const auto hop = ipv4(10, 0, 0, 1);
  const auto dest = ipv4(8, 8, 4, 4);
  const auto us = ipv4(192, 168, 0, 2);
  const auto inner = wrap_ipv4(us, dest, build_echo_request(1, 1, {}));
  const auto icmp =
      icmp_error(Icmpv4Type::kDestUnreachable,
                 static_cast<std::uint8_t>(Icmpv4UnreachCode::kHost), inner);
  const auto datagram = wrap_ipv4(hop, us, icmp);
  const auto reply = match_ipv4_probe_reply(datagram, hop, 1, 1);
  REQUIRE(reply.has_value());
  REQUIRE(reply->kind == ProbeReplyKind::kDestUnreachable);
  REQUIRE(reply->code == static_cast<std::uint8_t>(Icmpv4UnreachCode::kHost));
}

TEST_CASE("wrong identifier is ignored") {
  const auto dest = ipv4(8, 8, 8, 8);
  const auto pkt = as_echo_reply(build_echo_request(1, 1, {}));
  const auto reply = match_ipv4_probe_reply(pkt, dest, 2, 1);
  REQUIRE_FALSE(reply.has_value());
}

TEST_CASE("match_probe_reply dispatches only IPv4 ICMP echo") {
  const auto dest = ipv4(8, 8, 8, 8);
  const auto pkt = as_echo_reply(build_echo_request(1, 1, {}));

  ProbeSpec icmp;
  const auto ok = match_probe_reply(icmp, pkt, dest, 1, 1);
  REQUIRE(ok.has_value());
  REQUIRE(ok->kind == ProbeReplyKind::kEchoReply);

  ProbeSpec udp;
  udp.protocol = ProbeProtocol::kUdp;
  REQUIRE_FALSE(match_probe_reply(udp, pkt, dest, 1, 1).has_value());

  ProbeSpec v6;
  v6.family = AddressFamily::kIpv6;
  REQUIRE_FALSE(match_probe_reply(v6, pkt, dest, 1, 1).has_value());
}

TEST_CASE("unreach_tag is spec-specific") {
  ProbeSpec icmp;
  REQUIRE(std::string(unreach_tag(
              icmp, static_cast<std::uint8_t>(Icmpv4UnreachCode::kHost))) ==
          " !H");

  ProbeSpec udp;
  udp.protocol = ProbeProtocol::kUdp;
  REQUIRE(std::string(unreach_tag(udp, 1)) == " !U");
}

TEST_CASE("darwin-style garbage icmp checksum still matches") {
  // Darwin SOCK_DGRAM already validated the packet; the buffer checksum is
  // often junk. Requiring a valid checksum here drops every hop to "*".
  auto echo = as_echo_reply(build_echo_request(0x1234, 7, {}));
  echo[kIcmpChecksumOffset] ^= 0xFF;
  REQUIRE(
      match_ipv4_probe_reply(echo, ipv4(8, 8, 8, 8), 0x1234, 7).has_value());
}

TEST_CASE("zero icmp checksum field is accepted") {
  auto echo = as_echo_reply(build_echo_request(0x1234, 7, {}));
  echo[kIcmpChecksumOffset] = 0;
  echo[kIcmpChecksumOffset + 1] = 0;
  REQUIRE(
      match_ipv4_probe_reply(echo, ipv4(8, 8, 8, 8), 0x1234, 7).has_value());
}

TEST_CASE("truncated icmp is ignored") {
  const std::vector<std::uint8_t> pkt{8, 0, 0, 0};
  REQUIRE_FALSE(
      match_ipv4_probe_reply(pkt, ipv4(8, 8, 8, 8), 1, 1).has_value());
}

TEST_CASE("internet_checksum RFC 1071") {
  REQUIRE(internet_checksum({}) == 0xFFFFu);
  const std::uint8_t odd[] = {0x00, 0x01, 0x00, 0x02, 0x03};
  REQUIRE(internet_checksum(odd) == 0xFCFCu);
}

TEST_CASE("wrap_quoted_as_icmp_error quoted IPv4") {
  const auto dest = ipv4(8, 8, 4, 4);
  const auto us = ipv4(192, 168, 0, 2);
  const auto hop = ipv4(10, 0, 0, 1);
  const auto inner = wrap_ipv4(us, dest, build_echo_request(0xBEEF, 42, {}));
  const auto icmp = wrap_quoted_as_icmp_error(
      static_cast<std::uint8_t>(Icmpv4Type::kTimeExceeded),
      static_cast<std::uint8_t>(Icmpv4TimeExceededCode::kTtl), inner);
  REQUIRE(internet_checksum(icmp) == 0);
  const auto reply = match_ipv4_probe_reply(icmp, hop, 0xBEEF, 42);
  REQUIRE(reply.has_value());
  REQUIRE(reply->kind == ProbeReplyKind::kTimeExceeded);
  REQUIRE(reply->responder == hop);
}

TEST_CASE("wrap_quoted_as_icmp_error quoted bare ICMP echo") {
  const auto hop = ipv4(10, 0, 0, 1);
  const auto echo = build_echo_request(9, 3, {});
  const auto icmp = wrap_quoted_as_icmp_error(
      static_cast<std::uint8_t>(Icmpv4Type::kTimeExceeded), 0, echo);
  REQUIRE(icmp.size() == kIcmpHeaderBytes + kIpv4MinHeaderBytes + echo.size());
  REQUIRE(internet_checksum(icmp) == 0);
  const auto reply = match_ipv4_probe_reply(icmp, hop, 9, 3);
  REQUIRE(reply.has_value());
  REQUIRE(reply->kind == ProbeReplyKind::kTimeExceeded);
}

TEST_CASE("match time exceeded with IPv4 options in quoted header") {
  const auto hop = ipv4(10, 0, 0, 1);
  const auto dest = ipv4(8, 8, 4, 4);
  const auto us = ipv4(192, 168, 0, 2);
  auto inner = wrap_ipv4(us, dest, build_echo_request(0xBEEF, 42, {}));
  inner[0] = 0x46;
  inner.insert(inner.begin() + kIpv4MinHeaderBytes, 4, std::uint8_t{0});
  const auto icmp = icmp_error(
      Icmpv4Type::kTimeExceeded,
      static_cast<std::uint8_t>(Icmpv4TimeExceededCode::kTtl), inner);
  const auto datagram = wrap_ipv4(hop, us, icmp);
  const auto reply = match_ipv4_probe_reply(datagram, hop, 0xBEEF, 42);
  REQUIRE(reply.has_value());
  REQUIRE(reply->kind == ProbeReplyKind::kTimeExceeded);
  REQUIRE(reply->responder == hop);
}

TEST_CASE("wrap_quoted_as_icmp_error empty payload") {
  const auto icmp = wrap_quoted_as_icmp_error(
      static_cast<std::uint8_t>(Icmpv4Type::kDestUnreachable),
      static_cast<std::uint8_t>(Icmpv4UnreachCode::kHost), {});
  REQUIRE(icmp.size() == kIcmpHeaderBytes + kIpv4MinHeaderBytes);
  REQUIRE(internet_checksum(icmp) == 0);
  REQUIRE_FALSE(
      match_ipv4_probe_reply(icmp, ipv4(10, 0, 0, 1), 1, 1).has_value());
}
