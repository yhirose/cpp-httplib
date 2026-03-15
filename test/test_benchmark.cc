#include <httplib.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <sstream>
#include <thread>
#include <vector>

using namespace httplib;

static const int PORT = 11134;

static void performance_test(const char *host) {
  Server svr;

  svr.Get("/benchmark", [&](const Request & /*req*/, Response &res) {
    res.set_content("Benchmark Response", "text/plain");
  });

  auto listen_thread = std::thread([&]() { svr.listen(host, PORT); });
  auto se = detail::scope_exit([&] {
    svr.stop();
    listen_thread.join();
    ASSERT_FALSE(svr.is_running());
  });

  svr.wait_until_ready();

  Client cli(host, PORT);

  // Warm-up request to establish connection and resolve DNS
  auto warmup_res = cli.Get("/benchmark");
  ASSERT_TRUE(warmup_res); // Ensure server is responding correctly

  // Run multiple trials and collect timings
  const int num_trials = 20;
  std::vector<int64_t> timings;
  timings.reserve(num_trials);

  for (int i = 0; i < num_trials; i++) {
    auto start = std::chrono::high_resolution_clock::now();
    auto res = cli.Get("/benchmark");
    auto end = std::chrono::high_resolution_clock::now();

    auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();

    // Assertions after timing measurement to avoid overhead
    ASSERT_TRUE(res);
    EXPECT_EQ(StatusCode::OK_200, res->status);

    timings.push_back(elapsed);
  }

  // Calculate 25th percentile (lower quartile)
  std::sort(timings.begin(), timings.end());
  auto p25 = timings[num_trials / 4];

  // Format timings for output
  std::ostringstream timings_str;
  timings_str << "[";
  for (size_t i = 0; i < timings.size(); i++) {
    if (i > 0) timings_str << ", ";
    timings_str << timings[i];
  }
  timings_str << "]";

  // Localhost HTTP GET should be fast even in CI environments
  EXPECT_LE(p25, 5) << "25th percentile performance is too slow: " << p25
                    << "ms (Issue #1777). Timings: " << timings_str.str();
}

TEST(BenchmarkTest, localhost) { performance_test("localhost"); }

TEST(BenchmarkTest, v6) { performance_test("::1"); }
