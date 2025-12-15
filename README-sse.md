# SSEClient - Server-Sent Events Client

A simple, EventSource-like SSE client for C++11.

## Features

- **Auto-reconnect**: Automatically reconnects on connection loss
- **Last-Event-ID**: Sends last received ID on reconnect for resumption
- **retry field**: Respects server's reconnect interval
- **Event types**: Supports custom event types via `on_event()`
- **Async support**: Run in background thread with `start_async()`
- **C++11 compatible**: No C++14/17/20 features required

## Quick Start

```cpp
httplib::Client cli("http://localhost:8080");
httplib::sse::SSEClient sse(cli, "/events");

sse.on_message([](const httplib::sse::SSEMessage &msg) {
    std::cout << "Event: " << msg.event << std::endl;
    std::cout << "Data: " << msg.data << std::endl;
});

sse.start();  // Blocking, with auto-reconnect
```

## API Reference

### SSEMessage

```cpp
struct SSEMessage {
    std::string event;  // Event type (default: "message")
    std::string data;   // Event payload
    std::string id;     // Event ID
};
```

### SSEClient

#### Constructor

```cpp
// Basic
SSEClient(Client &client, const std::string &path);

// With custom headers
SSEClient(Client &client, const std::string &path, const Headers &headers);
```

#### Event Handlers

```cpp
// Called for all events (or events without a specific handler)
sse.on_message([](const SSEMessage &msg) { });

// Called for specific event types
sse.on_event("update", [](const SSEMessage &msg) { });
sse.on_event("delete", [](const SSEMessage &msg) { });

// Called when connection is established
sse.on_open([]() { });

// Called on connection errors
sse.on_error([](httplib::Error err) { });
```

#### Configuration

```cpp
// Set reconnect interval (default: 3000ms)
sse.set_reconnect_interval(5000);

// Set max reconnect attempts (default: 0 = unlimited)
sse.set_max_reconnect_attempts(10);
```

#### Control

```cpp
// Blocking start with auto-reconnect
sse.start();

// Non-blocking start (runs in background thread)
sse.start_async();

// Stop the client (thread-safe)
sse.stop();
```

#### State

```cpp
bool connected = sse.is_connected();
const std::string &id = sse.last_event_id();
```

## Examples

### Basic Usage

```cpp
httplib::Client cli("http://localhost:8080");
httplib::sse::SSEClient sse(cli, "/events");

sse.on_message([](const httplib::sse::SSEMessage &msg) {
    std::cout << msg.data << std::endl;
});

sse.start();
```

### With Custom Event Types

```cpp
httplib::sse::SSEClient sse(cli, "/events");

sse.on_event("notification", [](const httplib::sse::SSEMessage &msg) {
    std::cout << "Notification: " << msg.data << std::endl;
});

sse.on_event("update", [](const httplib::sse::SSEMessage &msg) {
    std::cout << "Update: " << msg.data << std::endl;
});

sse.start();
```

### Async with Stop

```cpp
httplib::sse::SSEClient sse(cli, "/events");

sse.on_message([](const httplib::sse::SSEMessage &msg) {
    std::cout << msg.data << std::endl;
});

sse.start_async();  // Returns immediately

// ... do other work ...

sse.stop();  // Stop when done
```

### With Custom Headers (e.g., Authentication)

```cpp
httplib::Headers headers = {
    {"Authorization", "Bearer token123"}
};

httplib::sse::SSEClient sse(cli, "/events", headers);
sse.start();
```

### Error Handling

```cpp
sse.on_error([](httplib::Error err) {
    std::cerr << "Error: " << httplib::to_string(err) << std::endl;
});

sse.set_reconnect_interval(1000);
sse.set_max_reconnect_attempts(5);

sse.start();
```

## SSE Protocol

The client parses SSE format according to the [W3C specification](https://html.spec.whatwg.org/multipage/server-sent-events.html):

```
event: custom-type
id: 123
data: {"message": "hello"}

data: simple message

: this is a comment (ignored)
```
