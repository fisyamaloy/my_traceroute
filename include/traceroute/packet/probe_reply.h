#pragma once

#include <cstdint>
#include <optional>

#include "traceroute/net/byte_span.h"
#include "traceroute/net/ip_address.h"
#include "traceroute/net/probe_spec.h"

namespace traceroute {
namespace packet {

enum class ProbeReplyKind {
  kEchoReply,
  kTimeExceeded,
  kDestUnreachable,
};

struct ProbeReply {
  ProbeReplyKind kind = ProbeReplyKind::kTimeExceeded;
  net::IpAddress responder;
  std::uint8_t code = 0;
};

[[nodiscard]] const char* unreach_tag(const net::ProbeSpec& spec,
                                      std::uint8_t code) noexcept;

[[nodiscard]] std::optional<ProbeReply> match_probe_reply(
    const net::ProbeSpec& spec, net::ByteSpan datagram,
    const net::IpAddress& recvfrom_src, std::uint16_t expect_id,
    std::uint16_t expect_seq);

}  // namespace packet
}  // namespace traceroute
