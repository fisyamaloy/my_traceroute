#pragma once

#include <cstdint>
#include <span>

namespace traceroute {
namespace packet {

[[nodiscard]] std::uint16_t internet_checksum(
    std::span<const std::uint8_t> data) noexcept;

}  // namespace packet
}  // namespace traceroute
