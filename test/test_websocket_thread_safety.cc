// Standalone test for TLS-session thread safety on wss:// connections.
//
// A wss:// WebSocket enters one TLS session from multiple threads: the read
// path, the application's send()/close(), and the heartbeat ping thread. A
// TLS session must never be entered concurrently, so httplib routes wss://
// through WebSocketSSLStream, which serializes every TLS call. These tests
// drive that concurrency directly. Built with ASan in CI, so a regression
// surfaces as a heap-buffer-overflow, not just a flaky assertion.

// Fire the heartbeat every second so the ping-vs-read case actually crosses a
// ping while the reader is idle.
#define CPPHTTPLIB_WEBSOCKET_PING_INTERVAL_SECOND 1
#include <httplib.h>

#include "gtest/gtest.h"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#ifdef CPPHTTPLIB_SSL_ENABLED

using namespace httplib;

namespace {

const size_t kPayloadBytes = 2048;
const size_t kSendCount = 2000;
const size_t kBurstPerFrame = 100;
const int kCloseCycles = 20;

} // namespace

class WebSocketTlsThreadSafetyTest : public ::testing::Test {
protected:
  WebSocketTlsThreadSafetyTest() : svr_("cert.pem", "key.pem") {}

  void TearDown() override {
    if (thread_.joinable()) {
      svr_.stop();
      thread_.join();
    }
  }

  // Registers the handler and starts the TLS server. Called by each test
  // after its own server configuration, since the heartbeat test needs the
  // pings the others switch off.
  bool start(Server::WebSocketHandler handler) {
    if (!svr_.is_valid()) { return false; }
    svr_.WebSocket("/ws", std::move(handler));
    port_ = svr_.bind_to_any_port("localhost");
    if (port_ <= 0) { return false; }
    thread_ = std::thread([this]() { svr_.listen_after_bind(); });
    svr_.wait_until_ready();
    return true;
  }

  std::string url() const {
    return "wss://localhost:" + std::to_string(port_) + "/ws";
  }

  SSLServer svr_;
  int port_ = 0;
  std::thread thread_;
};

// A sender thread hammers send() while another thread loops read(). Both
// enter the same TLS session, and every echoed frame must arrive intact.
TEST_F(WebSocketTlsThreadSafetyTest, SendWhileAnotherThreadReads) {
  svr_.set_websocket_ping_interval(0);
  ASSERT_TRUE(start([](const Request &, ws::WebSocket &sock) {
    std::string msg;
    while (sock.read(msg) != ws::ReadResult::Fail) {
      if (!sock.send(msg.data(), msg.size())) { break; }
    }
  }));

  ws::WebSocketClient cli(url());
  cli.enable_server_certificate_verification(false);
  ASSERT_TRUE(cli.connect());

  const std::string payload(kPayloadBytes, 'x');

  // close() drains the peer's Close reply with its own frame reader, so once
  // it starts, two threads parse frames from one stream and can split a
  // payload between them. That is frame-level, not TLS-level, and happens on
  // ws:// too, so only frames completed before close() are checked here.
  std::atomic<bool> closing(false);
  std::atomic<size_t> frames_read(0);
  std::atomic<size_t> corrupt_frames(0);
  std::thread reader([&]() {
    std::string msg;
    while (cli.read(msg) != ws::ReadResult::Fail) {
      if (msg != payload && !closing.load()) { corrupt_frames++; }
      frames_read++;
    }
  });

  size_t sent = 0;
  for (size_t i = 0; i < kSendCount; i++) {
    if (!cli.send(payload.data(), payload.size())) { break; }
    sent++;
  }

  closing.store(true);
  cli.close();
  reader.join();

  EXPECT_EQ(kSendCount, sent);
  EXPECT_EQ(static_cast<size_t>(0), corrupt_frames.load());
  EXPECT_GT(frames_read.load(), static_cast<size_t>(0));
}

// close() sends a Close frame and drains the peer's reply while a second
// thread is inside read(). Repeated to shake out the race.
TEST_F(WebSocketTlsThreadSafetyTest, CloseWhileAnotherThreadReads) {
  svr_.set_websocket_ping_interval(0);
  ASSERT_TRUE(start([](const Request &, ws::WebSocket &sock) {
    const std::string burst(64, 'p');
    std::string msg;
    while (sock.read(msg) != ws::ReadResult::Fail) {
      for (size_t i = 0; i < kBurstPerFrame; i++) {
        if (!sock.send(burst.data(), burst.size())) { return; }
      }
    }
  }));

  for (int cycle = 0; cycle < kCloseCycles; cycle++) {
    ws::WebSocketClient cli(url());
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

// The heartbeat ping thread writes to the TLS session on its own timer while
// the application blocks in read() with no traffic. The ping's write must not
// collide with the reader. The 1-second interval above means several pings
// fire on both sides during this idle window.
TEST_F(WebSocketTlsThreadSafetyTest, HeartbeatPingWhileReaderIsIdle) {
  ASSERT_TRUE(start([](const Request &, ws::WebSocket &sock) {
    std::string msg;
    while (sock.read(msg) != ws::ReadResult::Fail) {}
  }));

  ws::WebSocketClient cli(url());
  cli.enable_server_certificate_verification(false);
  ASSERT_TRUE(cli.connect());

  // No data frames are sent, so the reader stays parked inside read() while
  // both sides exchange pings and pongs on the heartbeat timer. read() only
  // returns once close() below tears the connection down.
  std::thread reader([&]() {
    std::string msg;
    while (cli.read(msg) != ws::ReadResult::Fail) {}
  });

  std::this_thread::sleep_for(std::chrono::seconds(4));

  // The connection survived the heartbeat exchange without a TLS-session race.
  EXPECT_TRUE(cli.is_open());

  cli.close();
  reader.join();
}

// A wss:// read decrypts whatever the socket already holds before it waits,
// so a peer that sends fragments faster than they are read never lets it
// wait. A close() made meanwhile still ends that read once the wait for the
// Close reply is over. The peer is a raw TLS client that floods continuation
// frames of a message it never ends, and never answers the Close.
TEST_F(WebSocketTlsThreadSafetyTest, CloseEndsAReadOfEndlessFragments) {
  svr_.set_websocket_ping_interval(0);
  // Shared with the handler, which may outlive a failed test until the server
  // stops
  struct Flags {
    std::atomic<bool> flooding{false};
    std::atomic<bool> handler_done{false};
  };
  auto flags = std::make_shared<Flags>();
  ASSERT_TRUE(start([flags](const Request &, ws::WebSocket &sock) {
    std::thread reader([&]() {
      std::string msg;
      while (sock.read(msg) != ws::ReadResult::Fail) {}
    });
    for (int i = 0; i < 500 && !flags->flooding; i++) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    sock.close();
    reader.join();
    flags->handler_done = true;
  }));

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *found = nullptr;
  ASSERT_EQ(0, getaddrinfo("localhost", std::to_string(port_).c_str(), &hints,
                           &found));
  auto sock = INVALID_SOCKET;
  for (auto ai = found; ai && sock == INVALID_SOCKET; ai = ai->ai_next) {
    sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock != INVALID_SOCKET &&
        ::connect(sock, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen))) {
      detail::close_socket(sock);
      sock = INVALID_SOCKET;
    }
  }
  freeaddrinfo(found);
  ASSERT_NE(INVALID_SOCKET, sock);
  auto ctx = tls::create_client_context();
  auto session = tls::create_session(ctx, sock);
  // Closed before the server stops, a failed assertion included, so the
  // server never waits on a connection left open
  auto se = detail::scope_exit([&] {
    tls::free_session(session);
    tls::free_context(ctx);
    detail::close_socket(sock);
  });
  ASSERT_EQ(tls::ErrorCode::Success, tls::connect(session).code);

  auto send_all = [&](const std::string &data) {
    size_t off = 0;
    while (off < data.size()) {
      tls::TlsError err;
      auto n = tls::write(session, data.data() + off, data.size() - off, err);
      if (n <= 0) { return false; }
      off += static_cast<size_t>(n);
    }
    return true;
  };
  ASSERT_TRUE(send_all("GET /ws HTTP/1.1\r\n"
                       "Host: localhost\r\n"
                       "Upgrade: websocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n"
                       "Sec-WebSocket-Version: 13\r\n"
                       "\r\n"));
  // A TLS 1.3 session ticket arrives first, which a read without auto-retry
  // reports as a want to read again
  std::string response;
  for (int tries = 0;
       tries < 1000 && response.find("\r\n\r\n") == std::string::npos;
       tries++) {
    char c;
    tls::TlsError err;
    auto n = tls::read(session, &c, 1, err);
    if (n == 1) {
      response += c;
    } else if (n == 0 || err.code != tls::ErrorCode::WantRead) {
      break;
    }
  }
  ASSERT_NE(std::string::npos, response.find(" 101 "));

  // Client frames with an all-zero mask key: a text frame that does not end,
  // then empty continuations, so the message never grows to its limit, in
  // batches large enough to keep the socket full
  auto frame = [](char first, const std::string &payload) {
    std::string f;
    f += first;
    f += static_cast<char>(0x80 | payload.size());
    f.append(4, '\0');
    return f + payload;
  };
  ASSERT_TRUE(send_all(frame('\x01', "a")));
  std::string batch;
  while (batch.size() < 65536) {
    batch += frame('\x00', "");
  }
  std::atomic<bool> sending(true);
  std::thread peer([&]() {
    while (sending && send_all(batch)) {
      flags->flooding = true;
    }
  });

  auto start_wait = std::chrono::steady_clock::now();
  auto bound =
      std::chrono::seconds(CPPHTTPLIB_WEBSOCKET_CLOSE_TIMEOUT_SECOND + 2);
  while (!flags->handler_done &&
         std::chrono::steady_clock::now() - start_wait < bound) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  const bool done_in_time = flags->handler_done;
  sending = false;
  ::shutdown(sock, 2);
  peer.join();
  EXPECT_TRUE(done_in_time);
}

#endif // CPPHTTPLIB_SSL_ENABLED
