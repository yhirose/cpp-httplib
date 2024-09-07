//
//  server_and_client.cc
//
//  Copyright (c) 2024 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <iostream>
#include <string>
#include <string>
#include <httplib.h>

using namespace httplib;

const char *HOST = "localhost";
const int PORT = 1234;

const std::string JSON_DATA = R"({"hello": "world"})";

int main(void) {
  Server svr;

  svr.Post("/api", [&](const Request & /*req*/, Response &res) {
    res.set_content("Hello World!", "text/plain");
  });

  auto thread = std::thread([&]() { svr.listen(HOST, PORT); });

  auto se = detail::scope_exit([&] {
    svr.stop();
    thread.join();
  });

  svr.wait_until_ready();

  Client cli(HOST, PORT);

  auto res =
      cli.Post("/api", Headers(), JSON_DATA.data(), JSON_DATA.size(),
               "application/json", [](uint64_t, uint64_t) { return true; });

  if (res) {
    std::cout << res->body << std::endl;
  }
}