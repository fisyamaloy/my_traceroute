#include <iostream>
#include <stdexcept>

#include "cli.h"
#include "traceroute/core/engine.h"
#include "traceroute/log/logger.h"
#include "traceroute/net/network_factory.h"

int main(int argc, char** argv) {
  try {
    const auto cli = traceroute::app::parse_cli(argc, argv);
    if (cli.help) {
      traceroute::app::print_help(std::cout);
      return 0;
    }
    auto factory = traceroute::net::make_network_factory();
    const traceroute::log::Logger log(std::cerr, cli.options.log_level);
    return traceroute::core::run(*factory, cli.options, std::cout, log);

  } catch (const std::invalid_argument& ex) {
    std::cerr << "traceroute: " << ex.what() << "\n";
    traceroute::app::print_help(std::cerr);
    return 2;
  } catch (const std::exception& ex) {
    std::cerr << "traceroute: " << ex.what() << "\n";
    return 1;
  }
}
