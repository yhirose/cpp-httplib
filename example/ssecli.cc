//
//  ssecli.cc
//
//  Copyright (c) 2026 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <httplib.h>

#include <csignal>
#include <iostream>

using namespace std;

// Global SSEClient pointer for signal handling
httplib::sse::SSEClient *g_sse = nullptr;

void signal_handler(int) {
  if (g_sse) { g_sse->stop(); }
}

int main(void) {
  // Configuration
  const string host = "http://localhost:1234";
  const string path = "/event1";

  cout << "SSE Client using httplib::sse::SSEClient\n";
  cout << "Connecting to: " << host << path << "\n";
  cout << "Press Ctrl+C to exit\n\n";

  httplib::Client cli(host);
  httplib::sse::SSEClient sse(cli, path);

  // Set up signal handler for graceful shutdown
  g_sse = &sse;
  signal(SIGINT, signal_handler);

  // Event handlers
  sse.on_open([]() { cout << "[Connected]\n\n"; });

  sse.on_message([](const httplib::sse::SSEMessage &msg) {
    cout << "Event: " << msg.event << "\n";
    cout << "Data:  " << msg.data << "\n";
    if (!msg.id.empty()) { cout << "ID:    " << msg.id << "\n"; }
    cout << "\n";
  });

  sse.on_error([](httplib::Error err) {
    cerr << "[Error] " << httplib::to_string(err) << "\n";
  });

  // Start with auto-reconnect (blocking)
  sse.start();

  cout << "\n[Disconnected]\n";
  return 0;
}
