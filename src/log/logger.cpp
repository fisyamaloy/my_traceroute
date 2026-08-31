#include "traceroute/log/logger.h"

#include <algorithm>
#include <format>
#include <ostream>
#include <string>

namespace traceroute {
namespace log {

void Logger::log(Level level, std::string_view message) const {
  if (!enabled(level)) {
    return;
  }
  *err_ << "traceroute: " << message << '\n' << std::flush;
}

std::string hex_dump(const std::span<const std::uint8_t> data,
                     std::size_t max_bytes) {
  if (data.empty()) {
    return {};
  }
  const std::size_t n = std::min(data.size(), max_bytes);
  std::string out;
  out.reserve(n * 3);
  for (std::size_t i = 0; i < n; ++i) {
    if (i != 0) {
      out.push_back(' ');
    }
    out += std::format("{:02x}", data[i]);
  }
  if (data.size() > max_bytes) {
    out += " ...";
  }
  return out;
}

}  // namespace log
}  // namespace traceroute
