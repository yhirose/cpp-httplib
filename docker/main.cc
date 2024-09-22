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
#include <csignal>
#include <string>
#include <filesystem>

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

std::string log(const httplib::Request &req, const httplib::Response &res) {
  auto remote_user = "-"; // TODO:
  auto request = std::format("{} {} {}", req.method, req.path, req.version);
  auto body_bytes_sent = res.get_header_value("Content-Length");
  auto http_referer = "-"; // TODO:
  auto http_user_agent = req.get_header_value("User-Agent", "-");

  // NOTE: From NGINX default access log format
  return std::format(R"({} - {} [{}] "{}" {} {} "{}" "{}")", req.remote_addr,
                     remote_user, time_local(), request, res.status,
                     body_bytes_sent, http_referer, http_user_agent);
}

int main(int argc, const char **argv) {
  // Default values for host, port, and base directory
  std::string base_dir = "./html";
  std::string host = "0.0.0.0";
  int port = 80;

  // Parse command-line arguments (if provided)
  if (argc > 1) base_dir = argv[1];
  if (argc > 2) host = argv[2];
  if (argc > 3) port = std::stoi(argv[3]);

  // Check if the base directory exists
  if (!std::filesystem::exists(base_dir)) {
    std::cerr << "Error: Directory " << base_dir << " does not exist." << std::endl;
    return 1;  // Exit if the directory is invalid
  }

  signal(SIGINT, sigint_handler);

  httplib::Server svr;

  // Set up multithreading with 8 threads
  svr.new_task_queue = [] { return new httplib::ThreadPool(8); };

  // Error handling for 404 and other status codes
  svr.set_error_handler([](const httplib::Request & /*req*/, httplib::Response &res) {
    auto body = std::format(error_html, res.status, httplib::status_message(res.status), CPPHTTPLIB_VERSION);
    res.set_content(body, "text/html");
  });

  // Set up logging
  svr.set_logger([](const httplib::Request &req, const httplib::Response &res) {
    std::cout << log(req, res) << std::endl;
  });

  // Mount the base directory for serving static files
  svr.set_mount_point("/", base_dir);

  // Start server and handle failures
  std::cout << std::format("Serving HTTP on {0} port {1} ...", host, port) << std::endl;
  auto ret = svr.listen(host.c_str(), port);

  if (!ret) {
    std::cerr << "Error: Failed to start server on " << host << ":" << port << std::endl;
    return 1;  // Exit with failure code if listen fails
  }

  return 0;
}
