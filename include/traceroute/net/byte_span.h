#pragma once

#include <cstdint>
#include <span>

namespace traceroute {
namespace net {

using ByteSpan = std::span<const std::uint8_t>;

}  // namespace net
}  // namespace traceroute
