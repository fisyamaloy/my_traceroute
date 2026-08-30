#include "cli.h"

#include <catch_amalgamated.hpp>
#include <chrono>
#include <stdexcept>

#include "traceroute/core/options.h"
#include "traceroute/log/logger.h"

using traceroute::app::parse_cli;
using traceroute::core::Options;

TEST_CASE("parse_cli host") {
  char a0[] = "traceroute";
  char a1[] = "example.com";
  char* argv[] = {a0, a1};
  const auto r = parse_cli(2, argv);
  REQUIRE_FALSE(r.help);
  REQUIRE(r.options.host == "example.com");
  REQUIRE(r.options.max_ttl == Options::kDefaultMaxTtl);
  REQUIRE(r.options.probes_per_hop == Options::kDefaultProbesPerHop);
}

TEST_CASE("parse_cli --help") {
  char a0[] = "traceroute";
  char a1[] = "--help";
  char* argv[] = {a0, a1};
  REQUIRE(parse_cli(2, argv).help);
}

TEST_CASE("parse_cli -h") {
  char a0[] = "traceroute";
  char a1[] = "-h";
  char* argv[] = {a0, a1};
  REQUIRE(parse_cli(2, argv).help);
}

TEST_CASE("parse_cli missing host") {
  char a0[] = "traceroute";
  char* argv[] = {a0};
  REQUIRE_THROWS_AS(parse_cli(1, argv), std::invalid_argument);
}

TEST_CASE("parse_cli -m -q -w") {
  char a0[] = "traceroute";
  char a1[] = "-m";
  char a2[] = "20";
  char a3[] = "-q";
  char a4[] = "3";
  char a5[] = "-w";
  char a6[] = "2";
  char a7[] = "8.8.8.8";
  char* argv[] = {a0, a1, a2, a3, a4, a5, a6, a7};
  const auto r = parse_cli(8, argv);
  REQUIRE(r.options.max_ttl == 20);
  REQUIRE(r.options.probes_per_hop == 3);
  REQUIRE(r.options.timeout == std::chrono::seconds(2));
  REQUIRE(r.options.host == "8.8.8.8");
}

TEST_CASE("parse_cli -m 0 is rejected") {
  char a0[] = "traceroute";
  char a1[] = "-m";
  char a2[] = "0";
  char a3[] = "example.com";
  char* argv[] = {a0, a1, a2, a3};
  REQUIRE_THROWS_AS(parse_cli(4, argv), std::invalid_argument);
}

TEST_CASE("parse_cli extra host is rejected") {
  char a0[] = "traceroute";
  char a1[] = "a.example";
  char a2[] = "b.example";
  char* argv[] = {a0, a1, a2};
  REQUIRE_THROWS_AS(parse_cli(3, argv), std::invalid_argument);
}

TEST_CASE("parse_cli -6 is unimplemented") {
  char a0[] = "traceroute";
  char a1[] = "-6";
  char a2[] = "example.com";
  char* argv[] = {a0, a1, a2};
  REQUIRE_THROWS_AS(parse_cli(3, argv), std::invalid_argument);
}

TEST_CASE("parse_cli IPv6 literal is unimplemented") {
  char a0[] = "traceroute";
  char a1[] = "2001:db8::1";
  char* argv[] = {a0, a1};
  REQUIRE_THROWS_AS(parse_cli(2, argv), std::invalid_argument);
}

TEST_CASE("parse_cli -U is unimplemented") {
  char a0[] = "traceroute";
  char a1[] = "-U";
  char a2[] = "example.com";
  char* argv[] = {a0, a1, a2};
  REQUIRE_THROWS_AS(parse_cli(3, argv), std::invalid_argument);
}

TEST_CASE("parse_cli unknown option") {
  char a0[] = "traceroute";
  char a1[] = "--nope";
  char a2[] = "example.com";
  char* argv[] = {a0, a1, a2};
  REQUIRE_THROWS_AS(parse_cli(3, argv), std::invalid_argument);
}

TEST_CASE("parse_cli -vv sets debug") {
  char a0[] = "traceroute";
  char a1[] = "-vv";
  char a2[] = "example.com";
  char* argv[] = {a0, a1, a2};
  REQUIRE(parse_cli(3, argv).options.log_level ==
          traceroute::log::Level::kDebug);
}
