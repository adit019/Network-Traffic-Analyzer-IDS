cmake_minimum_required(VERSION 3.16)
project(network_traffic_analyzer_ids C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_library(ntai
  src/capture.c
  src/dpi.c
  src/rules.c
  src/pipeline.c
)
target_include_directories(ntai PUBLIC include \)
target_link_libraries(ntai PUBLIC \)
target_compile_definitions(ntai PRIVATE _DEFAULT_SOURCE)

add_executable(nta ids src/main.c)
target_link_libraries(nta PRIVATE ntai)

add_executable(pcap_bench tools/pcap_bench.c)
target_link_libraries(pcap_bench PRIVATE ntai)

# ---- Tests ----
enable_testing()
add_executable(unit_tests tests/test_rules.c tests/test_dpi.c)
target_link_libraries(unit_tests PRIVATE ntai)
add_test(NAME unit COMMAND unit_tests)
