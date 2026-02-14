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
