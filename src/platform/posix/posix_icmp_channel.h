#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "platform/posix/unique_fd.h"
#include "traceroute/log/logger.h"
#include "traceroute/net/i_probe_channel.h"

namespace traceroute {
namespace net {
namespace posix {

// Shared ICMP probe loop (TTL / send / poll). Darwin uses the dgram subclass.
// Linux overrides consume() for SOCK_RAW and IP_RECVERR.
class PosixIcmpChannel : public IProbeChannel {
 public:
  PosixIcmpChannel(const PosixIcmpChannel&) = delete;
  PosixIcmpChannel& operator=(const PosixIcmpChannel&) = delete;
  PosixIcmpChannel(PosixIcmpChannel&&) = delete;
  PosixIcmpChannel& operator=(PosixIcmpChannel&&) = delete;
  ~PosixIcmpChannel() noexcept override = default;

  void set_hop_limit(int ttl) override;
  std::uint16_t send_probe(const IpAddress& dest, std::uint16_t seq,
                           const ByteSpan payload) override;
  std::optional<ReceivedPacket> receive(
      std::chrono::milliseconds timeout) override;

 protected:
  PosixIcmpChannel(log::Logger log, UniqueFd fd, std::uint16_t ident,
                   bool refresh_ident_after_send);

  [[nodiscard]] virtual short wait_events() const noexcept;
  [[nodiscard]] virtual std::optional<ReceivedPacket> consume(short revents);

  void refresh_identifier();
  [[nodiscard]] std::optional<ReceivedPacket> recv_datagram();

  UniqueFd fd_;
  log::Logger log_;
  std::uint16_t ident_ = 0;
  int hop_limit_ = 0;
  bool refresh_ident_after_send_ = true;

  static constexpr std::size_t kRecvBufBytes = 2048;
};

}  // namespace posix
}  // namespace net
}  // namespace traceroute
