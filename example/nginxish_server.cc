//
//  nginxish_server.cc
//
//  Copyright (c) 2025 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <chrono>
#include <ctime>
#include <httplib.h>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace httplib;

std::string get_nginx_time_format() {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);

  std::stringstream ss;
  ss << std::put_time(std::localtime(&time_t), "%d/%b/%Y:%H:%M:%S %z");
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
  std::string time_local = get_nginx_time_format();
  std::string request = req.method + " " + req.path + " HTTP/" + req.version;
  int status = res.status;
  size_t body_bytes_sent = res.body.size();
  std::string http_referer = req.get_header_value("Referer");
  if (http_referer.empty()) http_referer = "-";
  std::string http_user_agent = req.get_header_value("User-Agent");
  if (http_user_agent.empty()) http_user_agent = "-";

  std::cout << remote_addr << " - " << remote_user << " [" << time_local << "] "
            << "\"" << request << "\" " << status << " " << body_bytes_sent
            << " "
            << "\"" << http_referer << "\" \"" << http_user_agent << "\""
            << std::endl;
}

// NGINX Error log format:
// [time] [level] pid#tid: *cid message, client: client_ip, server: server_name,
// request: "request", host: "host"
void nginx_error_logger(const Request &req, const Error &err) {
  std::string time_local = get_nginx_time_format();
  std::string level = "error";
  std::string client_ip = get_client_ip(req);
  std::string server_name = req.get_header_value("Host");
  if (server_name.empty()) server_name = "-";
  std::string request = req.method + " " + req.path + " HTTP/" + req.version;
  std::string host = req.get_header_value("Host");
  if (host.empty()) host = "-";

  std::cerr << "[" << time_local << "] [" << level << "] " << to_string(err)
            << ", client: " << client_ip << ", server: " << server_name
            << ", request: \"" << request << "\""
            << ", host: \"" << host << "\"" << std::endl;
}

void print_usage(const char *program_name) {
  std::cerr << "Usage: " << program_name
            << " <hostname> <port> <mount_point> <document_root_directory>"
            << std::endl;
  std::cerr << "Example: " << program_name << " localhost 8080 /var/www/html ."
            << std::endl;
}

int main(int argc, char *argv[]) {
  if (argc != 5) {
    print_usage(argv[0]);
    return 1;
  }

  std::string hostname = argv[1];
  int port = std::atoi(argv[2]);
  std::string mount_point = argv[3];
  std::string document_root = argv[4];

  if (port <= 0 || port > 65535) {
    std::cerr << "Error: Invalid port number. Must be between 1 and 65535."
              << std::endl;
    return 1;
  }

  Server svr;

  // Set up NGINX-style logging
  svr.set_access_logger(nginx_access_logger);
  svr.set_error_logger(nginx_error_logger);

  // Set up static file serving
  auto ret = svr.set_mount_point(mount_point, document_root);
  if (!ret) {
    std::cerr << "Error: Cannot mount '" << mount_point << "' to '"
              << document_root << "'. Directory may not exist." << std::endl;
    return 1;
  }

  // Add some common MIME types (similar to NGINX)
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

  // Custom error handler for 404s
  svr.set_error_handler([](const Request & /*req*/, Response &res) {
    if (res.status == 404) {
      res.set_content(
          "<html><head><title>404 Not Found</title></head>"
          "<body><h1>404 Not Found</h1>"
          "<p>The requested resource was not found on this server.</p>"
          "<hr><p>nginxish_server/1.0</p></body></html>",
          "text/html");
    }
  });

  // Set server header to mimic NGINX
  svr.set_pre_routing_handler([](const Request & /*req*/, Response &res) {
    res.set_header("Server", "nginxish_server/1.0");
    return Server::HandlerResponse::Unhandled;
  });

  std::cout << "Starting nginxish_server on " << hostname << ":" << port
            << std::endl;
  std::cout << "Document root: " << document_root << std::endl;
  std::cout << "Mount point: " << mount_point << " -> " << document_root
            << std::endl;
  std::cout << "Press Ctrl+C to stop the server" << std::endl;

  // Start the server
  svr.listen(hostname, port);

  return 0;
}
