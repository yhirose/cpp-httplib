//
//  main.cc
//
//  Copyright (c) 2024 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <chrono>
#include <ctime>
#include <format>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <httplib.h>

constexpr auto error_html = R"(<html>
<head><title>{} {}</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>cpp-httplib/{}</center>
</body>
</html>
)";

void sigint_handler(int s) { exit(1); }

std::string time_local() {
  auto p = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(p);

  std::stringstream ss;
  ss << std::put_time(std::localtime(&t), "%d/%b/%Y:%H:%M:%S %z");
  return ss.str();
}

std::string log(auto &req, auto &res) {
  auto remote_user = "-"; // TODO:
  auto request = std::format("{} {} {}", req.method, req.path, req.version);
  auto body_bytes_sent = res.get_header_value("Content-Length");
  auto http_referer = "-"; // TODO:
  auto http_user_agent = req.get_header_value("User-Agent", "-");

  // NOTE: From NGINX defualt access log format
  // log_format combined '$remote_addr - $remote_user [$time_local] '
  //                     '"$request" $status $body_bytes_sent '
  //                     '"$http_referer" "$http_user_agent"';
  return std::format(R"({} - {} [{}] "{}" {} {} "{}" "{}")", req.remote_addr,
                     remote_user, time_local(), request, res.status,
                     body_bytes_sent, http_referer, http_user_agent);
}

int main(int argc, const char **argv) {
  signal(SIGINT, sigint_handler);

  auto base_dir = "./html";
  auto host = "0.0.0.0";
  auto port = 80;

  httplib::Server svr;

  svr.set_error_handler([](auto & /*req*/, auto &res) {
    auto body =
        std::format(error_html, res.status, httplib::status_message(res.status),
                    CPPHTTPLIB_VERSION);

    res.set_content(body, "text/html");
  });

  svr.set_logger(
      [](auto &req, auto &res) { std::cout << log(req, res) << std::endl; });

  svr.set_mount_point("/", base_dir);

  std::cout << std::format("Serving HTTP on {0} port {1} ...", host, port)
            << std::endl;

  auto ret = svr.listen(host, port);

  return ret ? 0 : 1;
}
