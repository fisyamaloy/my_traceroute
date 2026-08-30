cmake_minimum_required(VERSION 3.16)

project(traceroute
  VERSION 0.1.0
  DESCRIPTION "Traceroute analog"
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(TRACEROUTE_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)

include(CTest)
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/compiler_warnings.cmake")

# Layout:
#   include/traceroute/     public API, no OS headers
#   src/app/                CLI / main
#   src/core/               TTL loop (depends on INetworkFactory / IProbeChannel)
#   src/log/                stderr Logger (stdout stays the traceroute table)
#   src/packet/             checksum / ICMP parse
#   src/platform/posix/     shared POSIX (resolver, sockaddr, ICMP send/poll loop)
#   src/platform/linux/     Linux ICMP (SOCK_RAW / IP_RECVERR)
# Only IPv4 ICMP is implemented. ProbeSpec/factory are extension points.

add_library(traceroute_net STATIC)
add_library(traceroute::net ALIAS traceroute_net)

target_include_directories(traceroute_net
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_sources(traceroute_net PRIVATE
  src/core/engine.cpp
  src/log/logger.cpp
  src/net/ip_address.cpp
  src/packet/checksum.cpp
  src/packet/icmpv4.cpp
  src/packet/ipv4.cpp
  src/packet/probe_reply.cpp
)

if(APPLE)
  target_sources(traceroute_net PRIVATE
    src/platform/posix/posix_socket.cpp
    src/platform/posix/posix_icmp_channel.cpp
    src/platform/posix/posix_icmp_dgram_channel.cpp
    src/platform/posix/posix_network_factory.cpp
    src/platform/posix/posix_resolver.cpp
    src/platform/posix/posix_sockaddr.cpp
  )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_sources(traceroute_net PRIVATE
    src/platform/posix/posix_socket.cpp
    src/platform/posix/posix_icmp_channel.cpp
    src/platform/posix/posix_resolver.cpp
    src/platform/posix/posix_sockaddr.cpp
    src/platform/linux/linux_icmp_channel.cpp
    src/platform/linux/linux_network_factory.cpp
  )
else()
  message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

traceroute_set_warnings(traceroute_net)

add_library(traceroute_app STATIC src/app/cli.cpp)
add_library(traceroute::app ALIAS traceroute_app)
target_include_directories(traceroute_app PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src/app"
)
target_link_libraries(traceroute_app PUBLIC traceroute::net)
traceroute_set_warnings(traceroute_app)

add_executable(traceroute src/app/main.cpp)
target_link_libraries(traceroute PRIVATE traceroute::app)
traceroute_set_warnings(traceroute)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
