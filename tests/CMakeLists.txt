include(FetchContent)

# Download Catch2 sources only. Do not add_subdirectory — that compiles their
# ~90-file static lib. We build extras/catch_amalgamated.cpp (one TU) instead.
if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
endif()

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v3.16.0
  GIT_SHALLOW TRUE
)
FetchContent_GetProperties(Catch2)
if(NOT catch2_POPULATED)
  FetchContent_Populate(Catch2)
endif()

add_library(catch2_amalgam STATIC
  "${catch2_SOURCE_DIR}/extras/catch_amalgamated.cpp"
)
target_include_directories(catch2_amalgam SYSTEM PUBLIC
  "${catch2_SOURCE_DIR}/extras"
)
if(NOT MSVC)
  target_compile_options(catch2_amalgam PRIVATE -w)
endif()

add_executable(traceroute_tests
  packet_test.cpp
  engine_test.cpp
  cli_test.cpp
  resolver_test.cpp
)
target_include_directories(traceroute_tests PRIVATE
  "${CMAKE_SOURCE_DIR}/src"
)
target_link_libraries(traceroute_tests PRIVATE
  traceroute::app
  traceroute::net
  catch2_amalgam
)
traceroute_set_warnings(traceroute_tests)

list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
include(Catch)
catch_discover_tests(traceroute_tests DISCOVERY_MODE PRE_TEST)
