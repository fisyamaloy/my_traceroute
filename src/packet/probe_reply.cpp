#include "traceroute/packet/probe_reply.h"

#include "traceroute/packet/icmpv4.h"

namespace traceroute {
namespace packet {
namespace {

const char* icmpv4_unreach_tag(std::uint8_t code) noexcept {
  using enum Icmpv4UnreachCode;
  switch (static_cast<Icmpv4UnreachCode>(code)) {
    case kNet:
    case kNetUnknown:
    case kNetTos:
      return " !N";
    case kHost:
    case kHostUnknown:
    case kHostTos:
      return " !H";
    case kProtocol:
      return " !P";
    case kPort:
      return "";
    case kNeedFrag:
      return " !F";
    case kSrcFail:
      return " !S";
    case kNetProhibited:
    case kHostProhibited:
    case kFiltered:
      return " !X";
    case kPrecViolation:
      return " !V";
    case kPrecCutoff:
      return " !C";
    case kIsolated:
    default:
      return " !U";
  }
}

}  // namespace

const char* unreach_tag(const net::ProbeSpec& spec,
                        std::uint8_t code) noexcept {
  if (spec.family == net::AddressFamily::kIpv4 &&
      spec.protocol == net::ProbeProtocol::kIcmpEcho) {
    return icmpv4_unreach_tag(code);
  }
  return " !U";
}

std::optional<ProbeReply> match_probe_reply(const net::ProbeSpec& spec,
                                            net::ByteSpan datagram,
                                            const net::IpAddress& recvfrom_src,
                                            std::uint16_t expect_id,
                                            std::uint16_t expect_seq) {
  if (spec.family == net::AddressFamily::kIpv4 &&
      spec.protocol == net::ProbeProtocol::kIcmpEcho) {
    return match_ipv4_probe_reply(datagram, recvfrom_src, expect_id,
                                  expect_seq);
  }
  return std::nullopt;
}

}  // namespace packet
}  // namespace traceroute
