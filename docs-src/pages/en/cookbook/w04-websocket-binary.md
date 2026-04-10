---
title: "W04. Send and Receive Binary Frames"
order: 54
status: "draft"
---

WebSocket has two frame types: text and binary. JSON and plain text go in text frames; images and raw protocol bytes go in binary. In cpp-httplib, `send()` picks the right type via overload.

## How to pick a frame type

```cpp
ws.send(std::string("Hello"));           // text
ws.send("Hello", 5);                      // binary
ws.send(binary_data, binary_data_size);   // binary
```

The `std::string` overload sends as **text**. The `const char*` + size overload sends as **binary**. A bit subtle, but once you know it, it sticks.

If you have a `std::string` and want to send it as binary, pass `.data()` and `.size()` explicitly.

```cpp
std::string raw = build_binary_payload();
ws.send(raw.data(), raw.size()); // binary frame
```

## Detect frame type on receive

The return value of `ws.read()` tells you whether the received frame was text or binary.

```cpp
std::string msg;
auto result = ws.read(msg);

switch (result) {
  case httplib::ws::ReadResult::Text:
    std::cout << "text: " << msg << std::endl;
    break;
  case httplib::ws::ReadResult::Binary:
    std::cout << "binary: " << msg.size() << " bytes" << std::endl;
    handle_binary(msg.data(), msg.size());
    break;
  case httplib::ws::ReadResult::Fail:
    // error or closed
    break;
}
```

Binary frames still come back in a `std::string`, but treat its contents as raw bytes — use `msg.data()` and `msg.size()`.

## When binary is the right call

- **Images, video, audio**: No Base64 overhead
- **Custom protocols**: protobuf, MessagePack, or any structured binary format
- **Game networking**: When latency matters
- **Sensor data streams**: Push numeric arrays directly

## Ping is binary-ish, but hidden

WebSocket Ping/Pong frames are close cousins of binary frames at the opcode level, but cpp-httplib handles them automatically — you don't touch them. See W02. Set a WebSocket Heartbeat.

## Example: send an image

```cpp
// Server: push an image
svr.WebSocket("/image", [](const auto &req, auto &ws) {
  auto img = read_image_file("logo.png");
  ws.send(img.data(), img.size());
});
```

```cpp
// Client: receive and save
httplib::ws::WebSocketClient cli("ws://localhost:8080/image");
cli.connect();

std::string buf;
if (cli.read(buf) == httplib::ws::ReadResult::Binary) {
  std::ofstream ofs("received.png", std::ios::binary);
  ofs.write(buf.data(), buf.size());
}
```

You can mix text and binary in the same connection. A common pattern: JSON for control messages, binary for the actual data — you get efficient handling of metadata and payload both.

> **Note:** WebSocket frames don't have an infinite size limit. For very large data, chunk it in your application code. cpp-httplib can handle a big frame in one shot, but it does load it all into memory at once.
