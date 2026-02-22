# WebSocket - RFC 6455 WebSocket Support

A simple, blocking WebSocket implementation for C++11.

> [!IMPORTANT]
> This is a blocking I/O WebSocket implementation using a thread-per-connection model. If you need high-concurrency WebSocket support with non-blocking/async I/O (e.g., thousands of simultaneous connections), this is not the one that you want.

## Features

- **RFC 6455 compliant**: Full WebSocket protocol support
- **Server and Client**: Both sides included
- **SSL/TLS support**: `wss://` scheme for secure connections
- **Text and Binary**: Both message types supported
- **Automatic heartbeat**: Periodic Ping/Pong keeps connections alive
- **Subprotocol negotiation**: `Sec-WebSocket-Protocol` support for GraphQL, MQTT, etc.

## Quick Start

### Server

```cpp
httplib::Server svr;

svr.WebSocket("/ws", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
    std::string msg;
    while (ws.read(msg)) {
        ws.send("echo: " + msg);
    }
});

svr.listen("localhost", 8080);
```

### Client

```cpp
httplib::ws::WebSocketClient ws("ws://localhost:8080/ws");

if (ws.connect()) {
    ws.send("hello");

    std::string msg;
    if (ws.read(msg)) {
        std::cout << msg << std::endl;  // "echo: hello"
    }
    ws.close();
}
```

## API Reference

### ReadResult

```cpp
enum ReadResult : int {
    Fail   = 0,  // Connection closed or error
    Text   = 1,  // UTF-8 text message
    Binary = 2,  // Binary message
};
```

Returned by `read()`. Since `Fail` is `0`, the result works naturally in boolean contexts — `while (ws.read(msg))` continues until the connection closes. When you need to distinguish text from binary, check the return value directly.

### CloseStatus

```cpp
enum class CloseStatus : uint16_t {
    Normal = 1000,
    GoingAway = 1001,
    ProtocolError = 1002,
    UnsupportedData = 1003,
    NoStatus = 1005,
    Abnormal = 1006,
    InvalidPayload = 1007,
    PolicyViolation = 1008,
    MessageTooBig = 1009,
    MandatoryExtension = 1010,
    InternalError = 1011,
};
```

### Server Registration

```cpp
// Basic handler
Server &WebSocket(const std::string &pattern, WebSocketHandler handler);

// With subprotocol negotiation
Server &WebSocket(const std::string &pattern, WebSocketHandler handler,
                  SubProtocolSelector sub_protocol_selector);
```

**Type aliases:**

```cpp
using WebSocketHandler =
    std::function<void(const Request &, ws::WebSocket &)>;
using SubProtocolSelector =
    std::function<std::string(const std::vector<std::string> &protocols)>;
```

The `SubProtocolSelector` receives the list of subprotocols proposed by the client (from the `Sec-WebSocket-Protocol` header) and returns the selected one. Return an empty string to decline all proposed subprotocols.

### WebSocket (Server-side)

Passed to the handler registered with `Server::WebSocket()`. The handler runs in a dedicated thread per connection.

```cpp
// Read next message (blocks until received, returns Fail/Text/Binary)
ReadResult read(std::string &msg);

// Send messages
bool send(const std::string &data);              // Text
bool send(const char *data, size_t len);          // Binary

// Close the connection
void close(CloseStatus status = CloseStatus::Normal,
           const std::string &reason = "");

// Access the original HTTP upgrade request
const Request &request() const;

// Check if the connection is still open
bool is_open() const;
```

### WebSocketClient

```cpp
// Constructor - accepts ws:// or wss:// URL
explicit WebSocketClient(const std::string &scheme_host_port_path,
                         const Headers &headers = {});

// Check if the URL was parsed successfully
bool is_valid() const;

// Connect (performs HTTP upgrade handshake)
bool connect();

// Get the subprotocol selected by the server (empty if none)
const std::string &subprotocol() const;

// Read/Send/Close (same as server-side WebSocket)
ReadResult read(std::string &msg);
bool send(const std::string &data);
bool send(const char *data, size_t len);
void close(CloseStatus status = CloseStatus::Normal,
           const std::string &reason = "");
bool is_open() const;

// Timeouts
void set_read_timeout(time_t sec, time_t usec = 0);
void set_write_timeout(time_t sec, time_t usec = 0);

// SSL configuration (wss:// only, requires CPPHTTPLIB_OPENSSL_SUPPORT)
void set_ca_cert_path(const std::string &path);
void set_ca_cert_store(tls::ca_store_t store);
void enable_server_certificate_verification(bool enabled);
```

## Examples

### Echo Server with Connection Logging

```cpp
httplib::Server svr;

svr.WebSocket("/ws", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
    std::cout << "Connected from " << req.remote_addr << std::endl;

    std::string msg;
    while (ws.read(msg)) {
        ws.send("echo: " + msg);
    }

    std::cout << "Disconnected" << std::endl;
});

svr.listen("localhost", 8080);
```

### Client: Continuous Read Loop

```cpp
httplib::ws::WebSocketClient ws("ws://localhost:8080/ws");

if (ws.connect()) {
    ws.send("hello");
    ws.send("world");

    std::string msg;
    while (ws.read(msg)) {           // blocks until a message arrives
        std::cout << msg << std::endl; // "echo: hello", "echo: world"
    }
    // read() returns false when the server closes the connection
}
```

### Text and Binary Messages

Check the `ReadResult` return value to distinguish between text and binary:

```cpp
// Server
svr.WebSocket("/ws", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
    std::string msg;
    httplib::ws::ReadResult ret;
    while ((ret = ws.read(msg))) {
        if (ret == httplib::ws::Text) {
            ws.send("echo: " + msg);
        } else {
            ws.send(msg.data(), msg.size());  // Binary echo
        }
    }
});

// Client
httplib::ws::WebSocketClient ws("ws://localhost:8080/ws");
if (ws.connect()) {
    // Send binary data
    const char binary[] = {0x00, 0x01, 0x02, 0x03};
    ws.send(binary, sizeof(binary));

    // Receive and check the type
    std::string msg;
    if (ws.read(msg) == httplib::ws::Binary) {
        // Process binary data in msg
    }
    ws.close();
}
```

### SSL Client

```cpp
httplib::ws::WebSocketClient ws("wss://echo.example.com/ws");

if (ws.connect()) {
    ws.send("hello over TLS");

    std::string msg;
    if (ws.read(msg)) {
        std::cout << msg << std::endl;
    }
    ws.close();
}
```

### Close with Status

```cpp
// Client-side: close with a specific status code and reason
ws.close(httplib::ws::CloseStatus::GoingAway, "shutting down");

// Server-side: close with a policy violation status
ws.close(httplib::ws::CloseStatus::PolicyViolation, "forbidden");
```

### Accessing the Upgrade Request

```cpp
svr.WebSocket("/ws", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
    // Access headers from the original HTTP upgrade request
    auto auth = req.get_header_value("Authorization");
    if (auth.empty()) {
        ws.close(httplib::ws::CloseStatus::PolicyViolation, "unauthorized");
        return;
    }

    std::string msg;
    while (ws.read(msg)) {
        ws.send("echo: " + msg);
    }
});
```

### Custom Headers and Timeouts

```cpp
httplib::Headers headers = {
    {"Authorization", "Bearer token123"}
};

httplib::ws::WebSocketClient ws("ws://localhost:8080/ws", headers);
ws.set_read_timeout(30, 0);   // 30 seconds
ws.set_write_timeout(10, 0);  // 10 seconds

if (ws.connect()) {
    std::string msg;
    while (ws.read(msg)) {
        std::cout << msg << std::endl;
    }
}
```

### Subprotocol Negotiation

The server can negotiate a subprotocol with the client using `Sec-WebSocket-Protocol`. This is required for protocols like GraphQL over WebSocket (`graphql-ws`) and MQTT.

```cpp
// Server: register a handler with a subprotocol selector
svr.WebSocket(
    "/ws",
    [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
        std::string msg;
        while (ws.read(msg)) {
            ws.send("echo: " + msg);
        }
    },
    [](const std::vector<std::string> &protocols) -> std::string {
        // The client proposed a list of subprotocols; pick one
        for (const auto &p : protocols) {
            if (p == "graphql-ws" || p == "graphql-transport-ws") {
                return p;
            }
        }
        return "";  // Decline all
    });

// Client: propose subprotocols via Sec-WebSocket-Protocol header
httplib::Headers headers = {
    {"Sec-WebSocket-Protocol", "graphql-ws, graphql-transport-ws"}
};
httplib::ws::WebSocketClient ws("ws://localhost:8080/ws", headers);

if (ws.connect()) {
    // Check which subprotocol the server selected
    std::cout << "Subprotocol: " << ws.subprotocol() << std::endl;
    // => "graphql-ws"
    ws.close();
}
```

### SSL Client with Certificate Configuration

```cpp
httplib::ws::WebSocketClient ws("wss://example.com/ws");
ws.set_ca_cert_path("/path/to/ca-bundle.crt");
ws.enable_server_certificate_verification(true);

if (ws.connect()) {
    ws.send("secure message");
    ws.close();
}
```

## Configuration

| Macro                                       | Default           | Description                                              |
|---------------------------------------------|-------------------|----------------------------------------------------------|
| `CPPHTTPLIB_WEBSOCKET_MAX_PAYLOAD_LENGTH`   | `16777216` (16MB) | Maximum payload size per message                         |
| `CPPHTTPLIB_WEBSOCKET_READ_TIMEOUT_SECOND`  | `300`             | Read timeout for WebSocket connections (seconds)         |
| `CPPHTTPLIB_WEBSOCKET_CLOSE_TIMEOUT_SECOND` | `5`               | Timeout for waiting peer's Close response (seconds)      |
| `CPPHTTPLIB_WEBSOCKET_PING_INTERVAL_SECOND` | `30`              | Automatic Ping interval for heartbeat (seconds)          |

## Threading Model

WebSocket connections share the same thread pool as HTTP requests. Each WebSocket connection occupies one thread for its entire lifetime.

The default thread pool uses dynamic scaling: it maintains a base thread count of `CPPHTTPLIB_THREAD_POOL_COUNT` (8 or `std::thread::hardware_concurrency() - 1`, whichever is greater) and can scale up to 4x that count under load (`CPPHTTPLIB_THREAD_POOL_MAX_COUNT`). When all base threads are busy, temporary threads are spawned automatically up to the maximum. These dynamic threads exit after an idle timeout (`CPPHTTPLIB_THREAD_POOL_IDLE_TIMEOUT`, default 3 seconds).

This dynamic scaling helps accommodate WebSocket connections alongside HTTP requests. However, if you expect many simultaneous WebSocket connections, you should configure the thread pool accordingly:

```cpp
httplib::Server svr;

svr.new_task_queue = [] {
  return new httplib::ThreadPool(/*base_threads=*/8, /*max_threads=*/128);
};
```

Choose sizes that account for both your expected HTTP load and the maximum number of simultaneous WebSocket connections.

## Protocol

The implementation follows [RFC 6455](https://tools.ietf.org/html/rfc6455):

- Handshake via HTTP Upgrade with `Sec-WebSocket-Key` / `Sec-WebSocket-Accept`
- Subprotocol negotiation via `Sec-WebSocket-Protocol`
- Frame masking (client-to-server)
- Control frames: Close, Ping, Pong
- Message fragmentation and reassembly
- Close handshake with status codes

## Browser Test

Run the echo server example and open `http://localhost:8080` in a browser:

```bash
cd example && make wsecho && ./wsecho
```
