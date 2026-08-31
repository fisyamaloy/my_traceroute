#include "traceroute/packet/checksum.h"

namespace traceroute {
namespace packet {

std::uint16_t internet_checksum(
    const std::span<const std::uint8_t> data) noexcept {
  std::uint32_t sum = 0;
  std::size_t i = 0;
  for (; i + 1 < data.size(); i += 2) {
    sum += (static_cast<std::uint32_t>(data[i]) << 8) |
           static_cast<std::uint32_t>(data[i + 1]);
  }
  if (i < data.size()) {
    sum += static_cast<std::uint32_t>(data[i]) << 8;
  }
  while ((sum >> 16) != 0) {
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  return static_cast<std::uint16_t>(~sum);
}

}  // namespace packet
}  // namespace traceroute
