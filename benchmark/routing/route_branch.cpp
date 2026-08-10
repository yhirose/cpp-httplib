#include<benchmark/benchmark.h>
#include<httplib.h>
#include<iostream>
#include<thread>

static void BM_E2E_MixedRoutingCost(benchmark::State& state){
    int n = state.range(0);
    int literal_route = 0;
    int paths_route = 0;
    int regex_route = 0;
    httplib::Server svr;
    for(int i = 0 ; i < n; i++){
      if(i % 3 == 0){
        svr.Get("/route" + std::to_string(i),
                [](const httplib::Request&, httplib::Response&){});
        literal_route = i;
      } else if (i % 3 == 1) {
        svr.Get("/route" + std::to_string(i) + "/:id",
                [](const httplib::Request&, httplib::Response&){});
        paths_route = i;
      } else {
        svr.Get("/route(\\d+)/" + std::to_string(i),
                [](const httplib::Request&, httplib::Response&){});
        regex_route = i;
      }
    }
    std::thread listen_thread([&](){svr.listen("localhost", 8080);});
    svr.wait_until_ready();
    httplib::Client cli("localhost", 8080);
    cli.Get("/route0");
    for (auto _ : state){
      cli.Get("/route" + std::to_string(literal_route));
      cli.Get("/route" + std::to_string(paths_route) + "/somevalue");
      cli.Get("/route34333765432198765/" + std::to_string(regex_route));
    }

  svr.stop();
  listen_thread.join();
  cli.stop();
}

BENCHMARK(BM_E2E_MixedRoutingCost)->Arg(10)->Arg(1000)->Arg(5000)->Arg(10000);

static void BM_E2E_LiteralRoutingCost(benchmark::State& state){
    int n = state.range(0);
    httplib::Server svr;
    for (int i = 0; i < n; i++){
      svr.Get("/route" + std::to_string(i),
              [](const httplib::Request&, httplib::Response&){});
    }
    std::thread listen_thread([&](){svr.listen("localhost", 8081);});
    svr.wait_until_ready();
    httplib::Client cli("localhost", 8081);
    cli.Get("/route0");
    for (auto _ : state){
      cli.Get("/route" + std::to_string(n - 1));
    }

  svr.stop();
  listen_thread.join();
  cli.stop();
}

BENCHMARK(BM_E2E_LiteralRoutingCost)->Arg(10)->Arg(1000)->Arg(5000)->Arg(10000);

static void BM_E2E_RegexRoutingCost(benchmark::State& state){
    int n = state.range(0);
    httplib::Server svr;
    for (int i = 0; i < n; i++){
      svr.Get("/route(\\d+)/" + std::to_string(i),
              [](const httplib::Request&, httplib::Response&){});
    }
    std::thread listen_thread([&](){svr.listen("localhost", 8082);});
    svr.wait_until_ready();
    httplib::Client cli("localhost", 8082);
    cli.Get("/route1/0");
    for (auto _ : state){
      cli.Get("/route34333765432198765/" + std::to_string(n - 1));
    }

  svr.stop();
  listen_thread.join();
  cli.stop();
}

BENCHMARK(BM_E2E_RegexRoutingCost)->Arg(10)->Arg(1000)->Arg(5000)->Arg(10000);

static void BM_E2E_PathParamRoutingCost(benchmark::State& state){
    int n = state.range(0);
    httplib::Server svr;
    for (int i = 0; i < n; i++){
      svr.Get("/route" + std::to_string(i) + "/:id",
              [](const httplib::Request&, httplib::Response&){});
    }
    std::thread listen_thread([&](){svr.listen("localhost", 8083);});
    svr.wait_until_ready();
    httplib::Client cli("localhost", 8083);
    cli.Get("/route0/1");
    for (auto _ : state){
      cli.Get("/route" + std::to_string(n - 1) + "/somevalue");
    }

  svr.stop();
  listen_thread.join();
  cli.stop();
}

BENCHMARK(BM_E2E_PathParamRoutingCost)->Arg(10)->Arg(1000)->Arg(5000)->Arg(10000);

static void BM_Matcher_Literal(benchmark::State& state){
    int n = state.range(0);
    std::vector<httplib::detail::LiteralMatcher> matchers;
    matchers.reserve(n);
    for (int i = 0; i < n; i++){
      matchers.emplace_back("/route" + std::to_string(i));
    }
    httplib::Request req;
    req.path = "/route" + std::to_string(n - 1);
    for (auto _ : state){
      for (auto &m : matchers){
        if (m.match(req)) break;
      }
    }
}

BENCHMARK(BM_Matcher_Literal)->Arg(10)->Arg(1000)->Arg(5000)->Arg(10000);

static void BM_Matcher_Regex(benchmark::State& state){
    int n = state.range(0);
    std::vector<httplib::detail::RegexMatcher> matchers;
    matchers.reserve(n);
    for (int i = 0; i < n; i++){
      matchers.emplace_back("/route(\\d+)/" + std::to_string(i));
    }
    httplib::Request req;
    req.path = "/route34333765432198765/" + std::to_string(n - 1);
    for (auto _ : state){
      for (auto &m : matchers){
        if (m.match(req)) break;
      }
    }
}

BENCHMARK(BM_Matcher_Regex)->Arg(10)->Arg(1000)->Arg(5000)->Arg(10000);

static void BM_Matcher_PathParam(benchmark::State& state){
    int n = state.range(0);
    std::vector<httplib::detail::PathParamsMatcher> matchers;
    matchers.reserve(n);
    for (int i = 0; i < n; i++){
      matchers.emplace_back("/route" + std::to_string(i) + "/:id");
    }
    httplib::Request req;
    req.path = "/route" + std::to_string(n - 1) + "/somevalue";
    for (auto _ : state){
      for (auto &m : matchers){
        if (m.match(req)) break;
      }
    }
}

BENCHMARK(BM_Matcher_PathParam)->Arg(10)->Arg(1000)->Arg(5000)->Arg(10000);

BENCHMARK_MAIN();
