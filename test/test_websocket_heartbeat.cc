// Standalone test for WebSocket heartbeat and close() timing, compiled with
// short intervals and timeouts so the tests don't wait for the defaults.

#define CPPHTTPLIB_WEBSOCKET_PING_INTERVAL_SECOND 1
#define CPPHTTPLIB_WEBSOCKET_CLIENT_READ_TIMEOUT_SECOND 3
#define CPPHTTPLIB_WEBSOCKET_SERVER_READ_TIMEOUT_SECOND 3
#define CPPHTTPLIB_WEBSOCKET_CLOSE_TIMEOUT_SECOND 1
#include <httplib.h>

#include "gtest/gtest.h"

#include <future>

using namespace httplib;

class WebSocketHeartbeatTest : public ::testing::Test {
protected:
  void SetUp() override {
    svr_.WebSocket("/ws", [](const Request &, ws::WebSocket &ws) {
      std::string msg;
      while (ws.read(msg)) {
        ws.send(msg);
      }
    });

    port_ = svr_.bind_to_any_port("localhost");
    thread_ = std::thread([this]() { svr_.listen_after_bind(); });
    svr_.wait_until_ready();
  }

  void TearDown() override {
    svr_.stop();
    thread_.join();
  }

  Server svr_;
  int port_;
  std::thread thread_;
};

// Verify that an idle connection stays alive beyond the read timeout
// thanks to automatic heartbeat pings.
TEST_F(WebSocketHeartbeatTest, IdleConnectionStaysAlive) {
  ws::WebSocketClient client("ws://localhost:" + std::to_string(port_) + "/ws");
  ASSERT_TRUE(client.connect());

  // Sleep longer than read timeout (3s). Without heartbeat, the connection
  // would time out. With heartbeat pings every 1s, it stays alive.
  std::this_thread::sleep_for(std::chrono::seconds(5));

  // Connection should still be open
  ASSERT_TRUE(client.is_open());

  // Verify we can still exchange messages
  ASSERT_TRUE(client.send("hello after idle"));
  std::string msg;
  ASSERT_TRUE(client.read(msg));
  EXPECT_EQ("hello after idle", msg);

  client.close();
}

// Verify that set_websocket_ping_interval overrides the compile-time default
TEST_F(WebSocketHeartbeatTest, RuntimePingIntervalOverride) {
  // The server is already using the compile-time default (1s).
  // Create a client with a custom runtime interval.
  ws::WebSocketClient client("ws://localhost:" + std::to_string(port_) + "/ws");
  client.set_websocket_ping_interval(2);
  ASSERT_TRUE(client.connect());

  // Sleep longer than read timeout (3s). Client heartbeat at 2s keeps alive.
  std::this_thread::sleep_for(std::chrono::seconds(5));

  ASSERT_TRUE(client.is_open());
  ASSERT_TRUE(client.send("runtime interval"));
  std::string msg;
  ASSERT_TRUE(client.read(msg));
  EXPECT_EQ("runtime interval", msg);

  client.close();
}

// Verify that ping_interval=0 disables heartbeat without breaking basic I/O.
TEST_F(WebSocketHeartbeatTest, ZeroDisablesHeartbeat) {
  ws::WebSocketClient client("ws://localhost:" + std::to_string(port_) + "/ws");
  client.set_websocket_ping_interval(0);
  ASSERT_TRUE(client.connect());

  // Basic send/receive still works with heartbeat disabled
  ASSERT_TRUE(client.send("no client ping"));
  std::string msg;
  ASSERT_TRUE(client.read(msg));
  EXPECT_EQ("no client ping", msg);

  client.close();
}

// Verify that Server::set_websocket_ping_interval works at runtime
class WebSocketServerPingIntervalTest : public ::testing::Test {
protected:
  void SetUp() override {
    svr_.set_websocket_ping_interval(2);
    svr_.WebSocket("/ws", [](const Request &, ws::WebSocket &ws) {
      std::string msg;
      while (ws.read(msg)) {
        ws.send(msg);
      }
    });

    port_ = svr_.bind_to_any_port("localhost");
    thread_ = std::thread([this]() { svr_.listen_after_bind(); });
    svr_.wait_until_ready();
  }

  void TearDown() override {
    svr_.stop();
    thread_.join();
  }

  Server svr_;
  int port_;
  std::thread thread_;
};

TEST_F(WebSocketServerPingIntervalTest, ServerRuntimeInterval) {
  ws::WebSocketClient client("ws://localhost:" + std::to_string(port_) + "/ws");
  ASSERT_TRUE(client.connect());

  // Server ping interval is 2s; client uses compile-time default (1s).
  // Both keep the connection alive.
  std::this_thread::sleep_for(std::chrono::seconds(5));

  ASSERT_TRUE(client.is_open());
  ASSERT_TRUE(client.send("server interval"));
  std::string msg;
  ASSERT_TRUE(client.read(msg));
  EXPECT_EQ("server interval", msg);

  client.close();
}

// A peer that never sends anything: the server's heartbeat is disabled and its
// handler never calls read(). The pong timeout against such a peer is tested
// in test.cc (WebSocketTest.PongTimeoutEndsABlockedRead), where every CI job
// runs it.
class WebSocketSilentPeerTest : public ::testing::Test {
protected:
  void SetUp() override {
    svr_.set_websocket_ping_interval(0);
    svr_.WebSocket("/ws", [this](const Request &, ws::WebSocket &) {
      std::unique_lock<std::mutex> lock(handler_mutex_);
      handler_cv_.wait(lock, [this]() { return release_; });
    });

    port_ = svr_.bind_to_any_port("localhost");
    thread_ = std::thread([this]() { svr_.listen_after_bind(); });
    svr_.wait_until_ready();
  }

  void TearDown() override {
    {
      std::lock_guard<std::mutex> lock(handler_mutex_);
      release_ = true;
    }
    handler_cv_.notify_all();
    svr_.stop();
    thread_.join();
  }

  Server svr_;
  int port_;
  std::thread thread_;
  std::mutex handler_mutex_;
  std::condition_variable handler_cv_;
  bool release_ = false;
};

// The compile-time client read timeout (3s here) was never asked for through
// set_read_timeout(), so when it elapses read() reports Fail and closes the
// connection rather than handing back a Timeout on a still-open one.
TEST_F(WebSocketSilentPeerTest, CompileTimeClientReadTimeoutIsFail) {
  ws::WebSocketClient client("ws://localhost:" + std::to_string(port_) + "/ws");
  client.set_websocket_ping_interval(0);
  ASSERT_TRUE(client.connect());

  // Server pings are off and its handler never sends, so nothing arrives.
  std::string msg;
  EXPECT_EQ(client.read(msg), ws::Fail);
  EXPECT_FALSE(client.is_open());
}

// The compile-time server read timeout (3s here) is a backstop that reclaims
// the worker from a peer gone quiet, not a timeout the handler asked for. When
// it elapses read() must return Fail, so a handler written as
// `while (ws.read(msg))` ends instead of re-running its body with the previous
// message still in `msg`.
class WebSocketServerReadTimeoutTest : public ::testing::Test {
protected:
  void SetUp() override {
    svr_.set_websocket_ping_interval(0);
    svr_.WebSocket("/ws", [this](const Request &, ws::WebSocket &ws) {
      std::string msg;
      while (ws.read(msg)) {
        iterations_++;
        ws.send(msg);
      }
      handler_done_.set_value();
    });

    port_ = svr_.bind_to_any_port("localhost");
    thread_ = std::thread([this]() { svr_.listen_after_bind(); });
    svr_.wait_until_ready();
  }

  void TearDown() override {
    svr_.stop();
    thread_.join();
  }

  Server svr_;
  int port_;
  std::thread thread_;
  std::atomic<int> iterations_{0};
  std::promise<void> handler_done_;
};

TEST_F(WebSocketServerReadTimeoutTest, BackstopEndsHandlerLoop) {
  ws::WebSocketClient client("ws://localhost:" + std::to_string(port_) + "/ws");
  client.set_websocket_ping_interval(0); // nothing reaches the server's read()
  client.set_read_timeout(10, 0);        // fail rather than hang
  ASSERT_TRUE(client.connect());

  ASSERT_TRUE(client.send("hello"));
  std::string msg;
  ASSERT_EQ(client.read(msg), ws::Text);
  EXPECT_EQ("hello", msg);

  // The client now stays silent. The server's backstop elapses and the
  // handler returns, having run its loop body exactly once.
  auto done = handler_done_.get_future();
  ASSERT_EQ(done.wait_for(std::chrono::seconds(6)), std::future_status::ready);
  EXPECT_EQ(1, iterations_.load());

  EXPECT_EQ(client.read(msg), ws::Fail);
  EXPECT_FALSE(client.is_open());
}

// Verify that a responsive peer does NOT trigger the pong-timeout mechanism,
// even with a small max_missed_pongs budget. This is the positive counterpart
// of WebSocketTest.PongTimeoutEndsABlockedRead in test.cc: the client must
// actively drive read() so that incoming Pong frames are consumed and the
// unacked counter is reset.
TEST_F(WebSocketHeartbeatTest, ResponsivePeerNeverTimesOut) {
  ws::WebSocketClient client("ws://localhost:" + std::to_string(port_) + "/ws");
  client.set_websocket_max_missed_pongs(2);
  ASSERT_TRUE(client.connect());

  // Interactive loop over ~6s, longer than 2 ping intervals, so the
  // pong-timeout mechanism would trigger if pongs weren't being consumed.
  // Each iteration's read() also drains any pending Pong frame.
  for (int i = 0; i < 6; i++) {
    std::string text = "keepalive" + std::to_string(i);
    ASSERT_TRUE(client.send(text));
    std::string msg;
    ASSERT_TRUE(client.read(msg));
    EXPECT_EQ(text, msg);
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  EXPECT_TRUE(client.is_open());
  client.close();
}

// Verify that multiple heartbeat cycles work
TEST_F(WebSocketHeartbeatTest, MultipleHeartbeatCycles) {
  ws::WebSocketClient client("ws://localhost:" + std::to_string(port_) + "/ws");
  ASSERT_TRUE(client.connect());

  // Wait through several heartbeat cycles
  for (int i = 0; i < 3; i++) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    ASSERT_TRUE(client.is_open());
    std::string text = "msg" + std::to_string(i);
    ASSERT_TRUE(client.send(text));
    std::string msg;
    ASSERT_TRUE(client.read(msg));
    EXPECT_EQ(text, msg);
  }

  client.close();
}

// A raw client never answers the server's close() and sends `bytes`, `chunk`
// bytes at a time `gap` apart; close() must still return at its 1 s timeout.
static void expect_close_bounded(bool use_tls, const std::string &bytes,
                                 size_t chunk, std::chrono::milliseconds gap) {
  std::unique_ptr<Server> svr;
#ifdef CPPHTTPLIB_SSL_ENABLED
  if (use_tls) { svr.reset(new SSLServer("cert.pem", "key.pem")); }
#endif
  if (!svr) { svr.reset(new Server); }
  svr->set_websocket_ping_interval(0);

  std::atomic<bool> upgraded{false};
  std::atomic<bool> closed{false};
  std::chrono::steady_clock::duration close_took{};
  svr->WebSocket("/ws", [&](const Request &, ws::WebSocket &ws) {
    while (!upgraded) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    auto start = std::chrono::steady_clock::now();
    ws.close();
    close_took = std::chrono::steady_clock::now() - start;
    closed = true;
  });
  auto port = svr->bind_to_any_port("127.0.0.1");
  ASSERT_GT(port, 0);
  std::thread t([&] { svr->listen_after_bind(); });
  auto se = detail::scope_exit([&] {
    upgraded = true; // Releases the handler when an assertion bails out early
    svr->stop();
    t.join();
  });
  svr->wait_until_ready();

  auto sock = ::socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(INVALID_SOCKET, sock);
  auto sock_se = detail::scope_exit([&] { detail::close_socket(sock); });
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  ASSERT_EQ(0,
            ::connect(sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)));

  std::unique_ptr<Stream> strm;
#ifdef CPPHTTPLIB_SSL_ENABLED
  tls::ctx_t ctx = nullptr;
  tls::session_t session = nullptr;
  auto tls_se = detail::scope_exit([&] {
    if (session) { tls::free_session(session); }
    if (ctx) { tls::free_context(ctx); }
  });
  if (use_tls) {
    ctx = tls::create_client_context();
    tls::set_verify_client(ctx, false); // The test certificate is self-signed
    session = tls::create_session(ctx, sock);
    ASSERT_TRUE(tls::connect_nonblocking(session, sock, 5, 0, nullptr));
    strm.reset(new detail::SSLSocketStream(sock, session, 5, 0, 5, 0));
  }
#endif
  if (!strm) { strm.reset(new detail::SocketStream(sock, 5, 0, 5, 0)); }

  const std::string upgrade = "GET /ws HTTP/1.1\r\n"
                              "Host: 127.0.0.1\r\n"
                              "Upgrade: websocket\r\n"
                              "Connection: Upgrade\r\n"
                              "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n"
                              "Sec-WebSocket-Version: 13\r\n"
                              "\r\n";
  ASSERT_EQ(static_cast<ssize_t>(upgrade.size()),
            strm->write(upgrade.data(), upgrade.size()));
  std::string response;
  char c;
  while (response.find("\r\n\r\n") == std::string::npos &&
         strm->read(&c, 1) == 1) {
    response += c;
  }
  ASSERT_NE(std::string::npos, response.find(" 101 "));
  upgraded = true;

  // Without the bound, close() would wait as long as the client sends
  auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(4);
  while (!closed && std::chrono::steady_clock::now() < give_up) {
    for (size_t off = 0; off < bytes.size() && !closed;) {
      auto n = strm->write(bytes.data() + off,
                           (std::min)(chunk, bytes.size() - off));
      if (n <= 0) { break; }
      off += static_cast<size_t>(n);
      auto next = std::chrono::steady_clock::now() + gap;
      while (!closed && std::chrono::steady_clock::now() < next) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    }
  }
  while (!closed) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  EXPECT_LT(close_took, std::chrono::milliseconds(2500));
}

// Empty masked Ping frames, enough to keep the socket full
static std::string ping_flood() {
  const std::string ping("\x89\x80\0\0\0\0", 6);
  std::string bytes;
  while (bytes.size() < 64 * 1024) {
    bytes += ping;
  }
  return bytes;
}

// A masked 20-byte Ping; sent a byte at a time, it outlasts the close timeout
static std::string ping_with_payload() {
  return std::string("\x89\x8e\0\0\0\0", 6) + std::string(14, 'x');
}

TEST(WebSocketCloseTest, BoundedAgainstPeerThatKeepsSending) {
  expect_close_bounded(/*use_tls=*/false, ping_flood(), ping_flood().size(),
                       std::chrono::milliseconds(0));
}

TEST(WebSocketCloseTest, BoundedAgainstPeerThatTricklesAFrame) {
  expect_close_bounded(/*use_tls=*/false, ping_with_payload(), 1,
                       std::chrono::milliseconds(300));
}

#ifdef CPPHTTPLIB_SSL_ENABLED
TEST(WebSocketCloseTest, SSLBoundedAgainstPeerThatKeepsSending) {
  expect_close_bounded(/*use_tls=*/true, ping_flood(), ping_flood().size(),
                       std::chrono::milliseconds(0));
}

TEST(WebSocketCloseTest, SSLBoundedAgainstPeerThatTricklesAFrame) {
  expect_close_bounded(/*use_tls=*/true, ping_with_payload(), 1,
                       std::chrono::milliseconds(300));
}
#endif
