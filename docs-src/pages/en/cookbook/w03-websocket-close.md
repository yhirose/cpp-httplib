---
title: "W03. Handle Connection Close"
order: 53
status: "draft"
---

A WebSocket ends when either side closes it explicitly, or when the network drops. Handle close cleanly, and your cleanup and reconnect logic stays tidy.

## Detect a closed connection

When `ws.read()` returns `ReadResult::Fail`, the connection is gone — either cleanly or with an error. Break out of the loop and the handler will finish.

```cpp
svr.WebSocket("/chat", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
  std::string msg;
  while (ws.is_open()) {
    auto result = ws.read(msg);
    if (result == httplib::ws::ReadResult::Fail) {
      std::cout << "disconnected" << std::endl;
      break;
    }
    handle_message(ws, msg);
  }

  // cleanup runs once we're out of the loop
  cleanup_user_session(req);
});
```

You can also check `ws.is_open()` — it's the same signal from a different angle.

## Close from the server side

To close explicitly, call `close()`.

```cpp
ws.close(httplib::ws::CloseStatus::Normal, "bye");
```

The first argument is the close status; the second is an optional reason. Common `CloseStatus` values:

| Value | Meaning |
| --- | --- |
| `Normal` (1000) | Normal closure |
| `GoingAway` (1001) | Server is shutting down |
| `ProtocolError` (1002) | Protocol violation detected |
| `UnsupportedData` (1003) | Received data that can't be handled |
| `PolicyViolation` (1008) | Violated a policy |
| `MessageTooBig` (1009) | Message too large |
| `InternalError` (1011) | Server-side error |

## Close from the client side

The client API is identical.

```cpp
cli.close(httplib::ws::CloseStatus::Normal);
```

Destroying the client also closes the connection, but calling `close()` explicitly makes the intent clearer.

## Graceful shutdown

To notify in-flight clients that the server is going down, use `GoingAway`.

```cpp
ws.close(httplib::ws::CloseStatus::GoingAway, "server restarting");
```

The client can inspect that status and decide whether to reconnect.

## Example: a tiny chat with quit

```cpp
svr.WebSocket("/chat", [](const auto &req, auto &ws) {
  std::string msg;
  while (ws.is_open()) {
    if (ws.read(msg) == httplib::ws::ReadResult::Fail) break;

    if (msg == "/quit") {
      ws.send("goodbye");
      ws.close(httplib::ws::CloseStatus::Normal, "user quit");
      break;
    }

    ws.send("echo: " + msg);
  }
});
```

> **Note:** On a sudden network drop, `read()` returns `Fail` with no chance to call `close()`. Put your cleanup at the end of the handler, and both paths — clean close and abrupt disconnect — end up in the same place.
