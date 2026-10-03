---
title: "E03. 处理 SSE 重连"
order: 50
status: "draft"
---

SSE 连接会因为各种各样的网络原因而断开。客户端会自动尝试重连，因此让你的服务器从上次中断的地方继续是一个好主意。

## 读取 `Last-Event-ID`

客户端重连时，会在 `Last-Event-ID` 请求头中发送它收到的最后一个事件的 ID。服务器读取该值，并从下一个事件继续。

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  auto last_id = req.get_header_value("Last-Event-ID");
  int start = last_id.empty() ? 0 : std::stoi(last_id) + 1;

  res.set_chunked_content_provider(
    "text/event-stream",
    [start](size_t offset, httplib::DataSink &sink) mutable {
      static int next_id = 0;
      if (next_id < start) { next_id = start; }

      std::string msg = "id: " + std::to_string(next_id) + "\n"
                      + "data: event " + std::to_string(next_id) + "\n\n";
      sink.write(msg.data(), msg.size());
      ++next_id;

      std::this_thread::sleep_for(std::chrono::seconds(1));
      return true;
    });
});
```

首次连接时，`Last-Event-ID` 为空，因此从 `0` 开始。重连时，从下一个 ID 继续。事件历史由服务器负责 —— 你需要把最近的事件保存在某处。

## 设置重连间隔

发送 `retry:` 字段可以告诉客户端在重连之前等待多久，单位为毫秒。

```cpp
std::string msg = "retry: 5000\n\n";  // 5 秒后重连
sink.write(msg.data(), msg.size());
```

通常你会在开始时发送一次。在负载高峰或维护窗口期间，更长的重连间隔有助于减少重连风暴。

## 缓冲最近的事件

为了支持重连，请在服务器上保留一个滚动的事件缓冲区。

```cpp
struct EventBuffer {
  std::mutex mu;
  std::deque<std::pair<int, std::string>> events; // {id, data}
  int next_id = 0;

  void push(const std::string &data) {
    std::lock_guard<std::mutex> lock(mu);
    events.push_back({next_id++, data});
    if (events.size() > 1000) { events.pop_front(); }
  }

  std::vector<std::pair<int, std::string>> since(int id) {
    std::lock_guard<std::mutex> lock(mu);
    std::vector<std::pair<int, std::string>> out;
    for (const auto &e : events) {
      if (e.first >= id) { out.push_back(e); }
    }
    return out;
  }
};
```

当客户端重连时，调用 `since(last_id)` 发送它错过的所有事件。

## 保留多少

缓冲区大小是在内存与客户端能回溯多远之间的一种权衡。它取决于具体用例：

- 实时聊天：几分钟到半小时
- 通知：最近 N 条
- 交易数据：持久化到数据库，再从那里拉取

> **警告：** `Last-Event-ID` 是客户端提供的值 —— 不要盲目信任它。如果你把它当作数字读取，请校验范围。如果它是字符串，请做净化处理。
