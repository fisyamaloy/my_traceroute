#pragma once

#include <cstdint>

namespace traceroute {

inline std::uint16_t read_u16_be(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>((static_cast<unsigned>(p[0]) << 8) |
                                    static_cast<unsigned>(p[1]));
}

inline void write_u16_be(std::uint8_t* p, std::uint16_t value) noexcept {
  p[0] = static_cast<std::uint8_t>(value >> 8);
  p[1] = static_cast<std::uint8_t>(value);
}

inline std::uint32_t read_u32_be(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24) |
         (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) |
         static_cast<std::uint32_t>(p[3]);
}

inline void write_u32_be(std::uint8_t* p, std::uint32_t value) noexcept {
  p[0] = static_cast<std::uint8_t>(value >> 24);
  p[1] = static_cast<std::uint8_t>(value >> 16);
  p[2] = static_cast<std::uint8_t>(value >> 8);
  p[3] = static_cast<std::uint8_t>(value);
}

}  // namespace traceroute
