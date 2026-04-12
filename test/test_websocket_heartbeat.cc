// Standalone test for WebSocket automatic heartbeat.
// Compiled with a 1-second ping interval so we can verify heartbeat behavior
// without waiting 30 seconds.

#define CPPHTTPLIB_WEBSOCKET_PING_INTERVAL_SECOND 1
#define CPPHTTPLIB_WEBSOCKET_READ_TIMEOUT_SECOND 3
#include <httplib.h>

#include "gtest/gtest.h"

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

// Verify that the client detects a non-responsive peer via unacked-ping count.
// Setup: the server's heartbeat is disabled AND its handler never calls
// read(), so no automatic Pong reply is ever produced. The client sends
// pings but receives no pongs, and should close itself once the unacked
// ping count reaches max_missed_pongs.
class WebSocketPongTimeoutTest : public ::testing::Test {
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

TEST_F(WebSocketPongTimeoutTest, ClientDetectsNonResponsivePeer) {
  ws::WebSocketClient client("ws://localhost:" + std::to_string(port_) + "/ws");
  client.set_websocket_max_missed_pongs(2);
  ASSERT_TRUE(client.connect());
  ASSERT_TRUE(client.is_open());

  // Client pings every 1s (compile-time default in this test file).
  // With max_missed_pongs = 2, the heartbeat thread should self-close within
  // roughly 3s. Poll is_open() up to 6s.
  auto start = std::chrono::steady_clock::now();
  while (client.is_open() &&
         std::chrono::steady_clock::now() - start < std::chrono::seconds(6)) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  EXPECT_FALSE(client.is_open());
}

// Verify that a responsive peer does NOT trigger the pong-timeout mechanism,
// even with a small max_missed_pongs budget. This is the positive counterpart
// of ClientDetectsNonResponsivePeer: the client must actively drive read() so
// that incoming Pong frames are consumed and the unacked counter is reset.
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
