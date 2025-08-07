//
//  main.cc
//
//  Copyright (c) 2025 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <atomic>
#include <chrono>
#include <ctime>
#include <format>
#include <iomanip>
#include <iostream>
#include <signal.h>
#include <sstream>

#include <httplib.h>

using namespace httplib;

auto SERVER_NAME = std::format("cpp-httplib-server/{}", CPPHTTPLIB_VERSION);

Server svr;

void signal_handler(int signal) {
  if (signal == SIGINT || signal == SIGTERM) {
    std::cout << std::format("\nReceived signal, shutting down gracefully...")
              << std::endl;
    svr.stop();
  }
}

std::string get_time_format() {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);

  std::stringstream ss;
  ss << std::put_time(std::localtime(&time_t), "%d/%b/%Y:%H:%M:%S %z");
  return ss.str();
}

std::string get_error_time_format() {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);

  std::stringstream ss;
  ss << std::put_time(std::localtime(&time_t), "%Y/%m/%d %H:%M:%S");
  return ss.str();
}

std::string get_client_ip(const Request &req) {
  // Check for X-Forwarded-For header first (common in reverse proxy setups)
  auto forwarded_for = req.get_header_value("X-Forwarded-For");
  if (!forwarded_for.empty()) {
    // Get the first IP if there are multiple
    auto comma_pos = forwarded_for.find(',');
    if (comma_pos != std::string::npos) {
      return forwarded_for.substr(0, comma_pos);
    }
    return forwarded_for;
  }

  // Check for X-Real-IP header
  auto real_ip = req.get_header_value("X-Real-IP");
  if (!real_ip.empty()) { return real_ip; }

  // Fallback to remote address (though cpp-httplib doesn't provide this
  // directly) For demonstration, we'll use a placeholder
  return "127.0.0.1";
}

// NGINX Combined log format:
// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
// "$http_referer" "$http_user_agent"
void nginx_access_logger(const Request &req, const Response &res) {
  std::string remote_addr = get_client_ip(req);
  std::string remote_user =
      "-"; // cpp-httplib doesn't have built-in auth user tracking
  std::string time_local = get_time_format();
  std::string request =
      std::format("{} {} {}", req.method, req.path, req.version);
  int status = res.status;
  size_t body_bytes_sent = res.body.size();
  std::string http_referer = req.get_header_value("Referer");
  if (http_referer.empty()) http_referer = "-";
  std::string http_user_agent = req.get_header_value("User-Agent");
  if (http_user_agent.empty()) http_user_agent = "-";

  std::cout << std::format("{} - {} [{}] \"{}\" {} {} \"{}\" \"{}\"",
                           remote_addr, remote_user, time_local, request,
                           status, body_bytes_sent, http_referer,
                           http_user_agent)
            << std::endl;
}

// NGINX Error log format:
// YYYY/MM/DD HH:MM:SS [level] message, client: client_ip, request: "request",
// host: "host"
void nginx_error_logger(const Error &err, const Request *req) {
  std::string time_local = get_error_time_format();
  std::string level = "error";

  if (req) {
    std::string client_ip = get_client_ip(*req);
    std::string request =
        std::format("{} {} {}", req->method, req->path, req->version);
    std::string host = req->get_header_value("Host");
    if (host.empty()) host = "-";

    std::cerr << std::format("{} [{}] {}, client: {}, request: "
                             "\"{}\", host: \"{}\"",
                             time_local, level, to_string(err), client_ip,
                             request, host)
              << std::endl;
  } else {
    // If no request context, just log the error
    std::cerr << std::format("{} [{}] {}", time_local, level, to_string(err))
              << std::endl;
  }
}

void print_usage(const char *program_name) {
  std::cout << std::format("Usage: {} <hostname> <port> <mount_point> "
                           "<document_root_directory>",
                           program_name)
            << std::endl;

  std::cout << std::format("Example: {} localhost 8080 /var/www/html .",
                           program_name)
            << std::endl;
}

int main(int argc, char *argv[]) {
  if (argc != 5) {
    print_usage(argv[0]);
    return 1;
  }

  std::string hostname = argv[1];
  auto port = std::atoi(argv[2]);
  std::string mount_point = argv[3];
  std::string document_root = argv[4];

  svr.set_logger(nginx_access_logger);
  svr.set_error_logger(nginx_error_logger);

  auto ret = svr.set_mount_point(mount_point, document_root);
  if (!ret) {
    std::cerr
        << std::format(
               "Error: Cannot mount '{}' to '{}'. Directory may not exist.",
               mount_point, document_root)
        << std::endl;
    return 1;
  }

  svr.set_file_extension_and_mimetype_mapping("html", "text/html");
  svr.set_file_extension_and_mimetype_mapping("htm", "text/html");
  svr.set_file_extension_and_mimetype_mapping("css", "text/css");
  svr.set_file_extension_and_mimetype_mapping("js", "text/javascript");
  svr.set_file_extension_and_mimetype_mapping("json", "application/json");
  svr.set_file_extension_and_mimetype_mapping("xml", "application/xml");
  svr.set_file_extension_and_mimetype_mapping("png", "image/png");
  svr.set_file_extension_and_mimetype_mapping("jpg", "image/jpeg");
  svr.set_file_extension_and_mimetype_mapping("jpeg", "image/jpeg");
  svr.set_file_extension_and_mimetype_mapping("gif", "image/gif");
  svr.set_file_extension_and_mimetype_mapping("svg", "image/svg+xml");
  svr.set_file_extension_and_mimetype_mapping("ico", "image/x-icon");
  svr.set_file_extension_and_mimetype_mapping("pdf", "application/pdf");
  svr.set_file_extension_and_mimetype_mapping("zip", "application/zip");
  svr.set_file_extension_and_mimetype_mapping("txt", "text/plain");

  svr.set_error_handler([](const Request & /*req*/, Response &res) {
    if (res.status == 404) {
      res.set_content(
          std::format(
              "<html><head><title>404 Not Found</title></head>"
              "<body><h1>404 Not Found</h1>"
              "<p>The requested resource was not found on this server.</p>"
              "<hr><p>{}</p></body></html>",
              SERVER_NAME),
          "text/html");
    }
  });

  svr.set_pre_routing_handler([](const Request & /*req*/, Response &res) {
    res.set_header("Server", SERVER_NAME);
    return Server::HandlerResponse::Unhandled;
  });

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  std::cout << std::format("Serving HTTP on {}:{}", hostname, port)
            << std::endl;
  std::cout << std::format("Mount point: {} -> {}", mount_point, document_root)
            << std::endl;
  std::cout << std::format("Press Ctrl+C to shutdown gracefully...")
            << std::endl;

  ret = svr.listen(hostname, port);

  std::cout << std::format("Server has been shut down.") << std::endl;

  return ret ? 0 : 1;
}
