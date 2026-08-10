# Microbenchmark for Server::dispatch_request's route-matching cost
# (LiteralMatcher vs RegexMatcher vs PathParamsMatcher). Only built when
# explicitly requested — see HTTPLIB_BUILD_ROUTING_BENCHMARK in the
# top-level CMakeLists.txt.
#
# For meaningful numbers, configure the whole project in Release mode:
#   cmake -B build -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_BUILD_ROUTING_BENCHMARK=ON

include(FetchContent)

FetchContent_Declare(
  googlebenchmark
  GIT_REPOSITORY https://github.com/google/benchmark.git
  GIT_TAG v1.8.3
)

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googlebenchmark)

add_executable(route_branch route_branch.cpp)
target_link_libraries(route_branch PRIVATE httplib::httplib benchmark::benchmark)
