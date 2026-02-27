---
title: "WebSocket"
order: 8
draft: true
---

cpp-httplib supports WebSocket as well. Unlike HTTP request/response, WebSocket lets the server and client exchange messages in both directions. It's great for chat apps and real-time notifications.

Let's build an echo server and client right away.

## Echo Server

Here's an echo server that sends back whatever message it receives.

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server svr;

    svr.WebSocket("/ws", [](const httplib::Request &, httplib::ws::WebSocket &ws) {
        std::string msg;
        while (ws.read(msg)) {
            ws.send(msg);  // Send back the received message as-is
        }
    });

    std::cout << "Listening on port 8080..." << std::endl;
    svr.listen("0.0.0.0", 8080);
}
```

You register a WebSocket handler with `svr.WebSocket()`. It works just like `svr.Get()` and `svr.Post()` from Chapter 3.

Inside the handler, `ws.read(msg)` waits for a message. When the connection closes, `read()` returns `false`, so the loop exits. `ws.send(msg)` sends a message back.

## Connecting from a Client

Let's connect to the server using `httplib::ws::WebSocketClient`.

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::ws::WebSocketClient client("ws://localhost:8080/ws");

    if (!client.connect()) {
        std::cout << "Connection failed" << std::endl;
        return 1;
    }

    // Send a message
    client.send("Hello, WebSocket!");

    // Receive a response from the server
    std::string msg;
    if (client.read(msg)) {
        std::cout << msg << std::endl;  // Hello, WebSocket!
    }

    client.close();
}
```

Pass a URL in `ws://host:port/path` format to the constructor. Call `connect()` to start the connection, then use `send()` and `read()` to exchange messages.

## Text and Binary

WebSocket has two types of messages: text and binary. You can tell them apart by the return value of `read()`.

```cpp
svr.WebSocket("/ws", [](const httplib::Request &, httplib::ws::WebSocket &ws) {
    std::string msg;
    httplib::ws::ReadResult ret;
    while ((ret = ws.read(msg))) {
        if (ret == httplib::ws::Binary) {
            ws.send(msg.data(), msg.size());  // Send as binary
        } else {
            ws.send(msg);  // Send as text
        }
    }
});
```

- `ws.send(const std::string &)` — sends as a text message
- `ws.send(const char *, size_t)` — sends as a binary message

The client-side API is the same.

## Accessing Request Information

You can read HTTP request information from the handshake through the first argument `req` in the handler. This is handy for checking authentication tokens.

```cpp
svr.WebSocket("/ws", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
    auto token = req.get_header_value("Authorization");
    if (token.empty()) {
        ws.close(httplib::ws::CloseStatus::PolicyViolation, "unauthorized");
        return;
    }

    std::string msg;
    while (ws.read(msg)) {
        ws.send(msg);
    }
});
```

## Using WSS

WebSocket over HTTPS (WSS) is also supported. On the server side, just register a WebSocket handler on `httplib::SSLServer`.

```cpp
httplib::SSLServer svr("cert.pem", "key.pem");

svr.WebSocket("/ws", [](const httplib::Request &, httplib::ws::WebSocket &ws) {
    std::string msg;
    while (ws.read(msg)) {
        ws.send(msg);
    }
});

svr.listen("0.0.0.0", 8443);
```

On the client side, use the `wss://` scheme.

```cpp
httplib::ws::WebSocketClient client("wss://localhost:8443/ws");
```

## Next Steps

Now you know the basics of WebSocket. This wraps up the Tour.

The next page gives you a summary of features we didn't cover in the Tour.

**Next:** [What's Next](../09-whats-next)
