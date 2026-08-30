#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <span>
#include <string>
#include <string_view>

namespace traceroute {
namespace log {

enum class Level { kError, kWarn, kInfo, kDebug };

class Logger {
 public:
  Logger() noexcept = default;
  // Emits levels up to max_level (Error < Warn < Info < Debug).
  explicit Logger(std::ostream& err, Level max_level) noexcept
      : err_(&err), max_level_(max_level) {}

  [[nodiscard]] bool enabled(Level level) const noexcept {
    return err_ != nullptr &&
           static_cast<int>(level) <= static_cast<int>(max_level_);
  }

  void log(Level level, std::string_view message) const;

 private:
  std::ostream* err_ = nullptr;
  Level max_level_ = Level::kWarn;
};

[[nodiscard]] std::string hex_dump(const std::span<const std::uint8_t> data,
                                   std::size_t max_bytes = 32);

inline void bump_verbose(Level& level) noexcept {
  if (level == Level::kWarn) {
    level = Level::kInfo;
  } else if (level == Level::kInfo) {
    level = Level::kDebug;
  }
}

}  // namespace log
}  // namespace traceroute
