#pragma once

#include <iosfwd>

#include "traceroute/core/options.h"

namespace traceroute {
namespace app {

struct CliResult {
  core::Options options;
  bool help = false;
};

void print_help(std::ostream& out);
[[nodiscard]] CliResult parse_cli(int argc, char* const* argv);

}  // namespace app
}  // namespace traceroute
