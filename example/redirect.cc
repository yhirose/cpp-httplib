//
//  redirect.cc
//
//  Copyright (c) 2019 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <httplib.h>

#define SERVER_CERT_FILE "./cert.pem"
#define SERVER_PRIVATE_KEY_FILE "./key.pem"

using namespace httplib;

int main(void) {
  // HTTP server
  Server http;

  http.Get("/test", [](const Request & /*req*/, Response &res) {
    res.set_content("Test\n", "text/plain");
  });

  http.set_error_handler([](const Request & /*req*/, Response &res) {
    res.set_redirect("https://localhost:8081/");
  });

  // HTTPS server
  SSLServer https(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE);

  https.Get("/", [=](const Request & /*req*/, Response &res) {
    res.set_redirect("/hi");
  });

  https.Get("/hi", [](const Request & /*req*/, Response &res) {
    res.set_content("Hello World!\n", "text/plain");
  });

  https.Get("/stop", [&](const Request & /*req*/, Response & /*res*/) {
    https.stop();
    http.stop();
  });

  // Run servers
  auto httpThread = std::thread([&]() {
    http.listen("localhost", 8080);
  });

  auto httpsThread = std::thread([&]() {
    https.listen("localhost", 8081);
  });

  httpThread.join();
  httpsThread.join();

  return 0;
}
