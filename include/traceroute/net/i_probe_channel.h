#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

#include "traceroute/net/byte_span.h"
#include "traceroute/net/ip_address.h"
#include "traceroute/net/received_packet.h"

namespace traceroute {
namespace net {

class IProbeChannel {
 public:
  virtual ~IProbeChannel() = default;

  IProbeChannel(const IProbeChannel&) = delete;
  IProbeChannel& operator=(const IProbeChannel&) = delete;
  IProbeChannel(IProbeChannel&&) = delete;
  IProbeChannel& operator=(IProbeChannel&&) = delete;

  virtual void set_hop_limit(int ttl) = 0;

  // Sends one probe. Returns the ICMP id replies must match: for ping
  // sockets this is the kernel-assigned socket port (getsockname after
  // send), not the id we wrote into the userspace buffer.
  [[nodiscard]] virtual std::uint16_t send_probe(const IpAddress& dest,
                                                 std::uint16_t seq,
                                                 ByteSpan payload) = 0;
  [[nodiscard]] virtual std::optional<ReceivedPacket> receive(
      std::chrono::milliseconds timeout) = 0;

 protected:
  IProbeChannel() = default;
};

}  // namespace net
}  // namespace traceroute
