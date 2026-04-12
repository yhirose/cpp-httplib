---
title: "W01. Implement a WebSocket Echo Server and Client"
order: 51
status: "draft"
---

WebSocket is a protocol for **two-way** messaging between client and server. cpp-httplib provides APIs for both sides. Let's start with the simplest example: an echo server.

## Server: echo server

```cpp
#include <httplib.h>

int main() {
  httplib::Server svr;

  svr.WebSocket("/echo", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
    std::string msg;
    while (ws.is_open()) {
      auto result = ws.read(msg);
      if (result == httplib::ws::ReadResult::Fail) {
        break;
      }
      ws.send(msg); // echo back what we received
    }
  });

  svr.listen("0.0.0.0", 8080);
}
```

Register a WebSocket handler with `svr.WebSocket()`. By the time the handler runs, the WebSocket handshake is already complete. Inside the loop, just `ws.read()` and `ws.send()` to get a working echo.

The `read()` return value is a `ReadResult` enum:

- `ReadResult::Text`: received a text message
- `ReadResult::Binary`: received a binary message
- `ReadResult::Fail`: error, or connection closed

## Client: talk to the echo server

```cpp
#include <httplib.h>

int main() {
  httplib::ws::WebSocketClient cli("ws://localhost:8080/echo");
  if (!cli.connect()) {
    std::cerr << "failed to connect" << std::endl;
    return 1;
  }

  cli.send("Hello, WebSocket!");

  std::string msg;
  if (cli.read(msg) != httplib::ws::ReadResult::Fail) {
    std::cout << "received: " << msg << std::endl;
  }

  cli.close();
}
```

Use a `ws://` (plain) or `wss://` (TLS) URL. Call `connect()` to do the handshake, then `send()` and `read()` work the same as on the server side.

## Text vs. binary

`send()` has two overloads that let you choose the frame type.

```cpp
ws.send("Hello");                        // text frame
ws.send(binary_data, binary_data_size);  // binary frame
```

The `std::string` overload sends as **text**; the `const char*` + size overload sends as **binary**. A bit subtle, but once you know it, it's intuitive. See [W04. Send and receive binary frames](w04-websocket-binary) for details.

## Thread pool implications

A WebSocket handler holds its worker thread for the entire life of the connection — one connection per thread. For many concurrent clients, configure a dynamic thread pool.

```cpp
svr.new_task_queue = [] {
  return new httplib::ThreadPool(8, 128);
};
```

See [S21. Configure the thread pool](s21-thread-pool).

> **Note:** To run WebSocket over HTTPS, use `httplib::SSLServer` instead of `httplib::Server` — the same `WebSocket()` handler just works. On the client side, use a `wss://` URL.
