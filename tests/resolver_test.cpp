#include <catch_amalgamated.hpp>
#include <stdexcept>

#include "platform/posix/posix_resolver.h"
#include "traceroute/net/address_family.h"

using traceroute::net::AddressFamily;
using traceroute::net::posix::PosixResolver;

TEST_CASE("numeric IPv4 does not need DNS") {
  const PosixResolver resolver;
  REQUIRE(resolver.resolve("127.0.0.1", AddressFamily::kIpv4).to_string() ==
          "127.0.0.1");
  REQUIRE(resolver.resolve("8.8.8.8", AddressFamily::kIpv4).to_string() ==
          "8.8.8.8");
}

TEST_CASE("unknown host fails") {
  const PosixResolver resolver;
  REQUIRE_THROWS_AS(resolver.resolve("this-host-should-not-exist.invalid",
                                     AddressFamily::kIpv4),
                    std::runtime_error);
}

TEST_CASE("IPv6 family is rejected") {
  const PosixResolver resolver;
  REQUIRE_THROWS_AS(resolver.resolve("127.0.0.1", AddressFamily::kIpv6),
                    std::runtime_error);
}
