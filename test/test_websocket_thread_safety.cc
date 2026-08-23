#define CPPHTTPLIB_WEBSOCKET_PING_INTERVAL_SECOND 1
#include <httplib.h>

#include "gtest/gtest.h"

#include <atomic>
#include <string>
#include <thread>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

using namespace httplib;

namespace {

const size_t kPayloadBytes = 2048;
const size_t kSendCount = 2000;
const size_t kBurstPerFrame = 100;
const int kCloseCycles = 20;

} // namespace

TEST(WebSocketTlsThreadSafetyTest, SendWhileAnotherThreadReads) {
  SSLServer svr("cert.pem", "key.pem");
  ASSERT_TRUE(svr.is_valid());

  svr.set_websocket_ping_interval(0);

  svr.WebSocket("/ws", [](const Request &, ws::WebSocket &sock) {
    std::string msg;
    while (sock.read(msg) != ws::ReadResult::Fail) {
      if (!sock.send(msg.data(), msg.size())) { break; }
    }
  });

  auto port = svr.bind_to_any_port("localhost");
  ASSERT_GT(port, 0);
  auto listen_thread = std::thread([&]() { svr.listen_after_bind(); });
  auto se = detail::scope_exit([&]() {
    svr.stop();
    listen_thread.join();
  });
  svr.wait_until_ready();

  ws::WebSocketClient cli("wss://localhost:" + std::to_string(port) + "/ws");
  cli.enable_server_certificate_verification(false);
  ASSERT_TRUE(cli.connect());

  std::atomic<size_t> frames_read(0);
  std::thread reader([&]() {
    std::string msg;
    while (cli.read(msg) != ws::ReadResult::Fail) {
      frames_read++;
    }
  });

  const std::string payload(kPayloadBytes, 'x');
  size_t sent = 0;
  for (size_t i = 0; i < kSendCount; i++) {
    if (!cli.send(payload.data(), payload.size())) { break; }
    sent++;
  }

  cli.close();
  reader.join();

  EXPECT_EQ(kSendCount, sent);
  EXPECT_GT(frames_read.load(), static_cast<size_t>(0));
}

TEST(WebSocketTlsThreadSafetyTest, CloseWhileAnotherThreadReads) {
  SSLServer svr("cert.pem", "key.pem");
  ASSERT_TRUE(svr.is_valid());

  svr.set_websocket_ping_interval(0);

  svr.WebSocket("/ws", [](const Request &, ws::WebSocket &sock) {
    const std::string burst(64, 'p');
    std::string msg;
    while (sock.read(msg) != ws::ReadResult::Fail) {
      for (size_t i = 0; i < kBurstPerFrame; i++) {
        if (!sock.send(burst.data(), burst.size())) { return; }
      }
    }
  });

  auto port = svr.bind_to_any_port("localhost");
  ASSERT_GT(port, 0);
  auto listen_thread = std::thread([&]() { svr.listen_after_bind(); });
  auto se = detail::scope_exit([&]() {
    svr.stop();
    listen_thread.join();
  });
  svr.wait_until_ready();

  for (int cycle = 0; cycle < kCloseCycles; cycle++) {
    ws::WebSocketClient cli("wss://localhost:" + std::to_string(port) + "/ws");
    cli.enable_server_certificate_verification(false);
    ASSERT_TRUE(cli.connect()) << "cycle " << cycle;

    std::thread reader([&]() {
      std::string msg;
      while (cli.read(msg) != ws::ReadResult::Fail) {}
    });

    const std::string trigger(64, 't');
    ASSERT_TRUE(cli.send(trigger.data(), trigger.size()));

    cli.close();
    reader.join();
  }
}

#endif // CPPHTTPLIB_OPENSSL_SUPPORT