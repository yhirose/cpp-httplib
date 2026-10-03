---
title: "S02. 接收 JSON 请求并返回 JSON 响应"
order: 21
status: "draft"
---

cpp-httplib 不包含 JSON 解析器。在服务器端，可以将其与 [nlohmann/json](https://github.com/nlohmann/json) 之类的库配合使用。下面的示例使用 `nlohmann/json`。

## 接收并返回 JSON

```cpp
#include <httplib.h>
#include <nlohmann/json.hpp>

int main() {
  httplib::Server svr;

  svr.Post("/api/users", [](const httplib::Request &req, httplib::Response &res) {
    try {
      auto in = nlohmann::json::parse(req.body);

      nlohmann::json out = {
        {"id", 42},
        {"name", in["name"]},
        {"created_at", "2026-04-10T12:00:00Z"},
      };

      res.status = 201;
      res.set_content(out.dump(), "application/json");
    } catch (const std::exception &e) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid json\"}", "application/json");
    }
  });

  svr.listen("0.0.0.0", 8080);
}
```

`req.body` 是一个普通的 `std::string`，因此你可以直接将它传给 JSON 库。对于响应，用 `dump()` 转成字符串，并将 Content-Type 设置为 `application/json`。

## 检查 Content-Type

```cpp
svr.Post("/api/users", [](const httplib::Request &req, httplib::Response &res) {
  auto content_type = req.get_header_value("Content-Type");
  if (content_type.find("application/json") == std::string::npos) {
    res.status = 415; // 不支持的媒体类型
    return;
  }
  // ...
});
```

当你严格要求只接受 JSON 时，请预先验证 Content-Type。

## 用于 JSON 响应的辅助函数

如果你反复编写相同的模式，一个小型辅助函数可以省去不少输入。

```cpp
auto send_json = [](httplib::Response &res, int status, const nlohmann::json &j) {
  res.status = status;
  res.set_content(j.dump(), "application/json");
};

svr.Get("/api/health", [&](const auto &req, auto &res) {
  send_json(res, 200, {{"status", "ok"}});
});
```

> **注意：** 大型 JSON 请求体会完全进入 `req.body`，这意味着它会全部驻留在内存中。对于超大负载，可以考虑流式接收——请参阅 [S07. 以流的方式接收 multipart 数据](../s07-multipart-reader)。

> 关于客户端，请参阅 [C02. 发送和接收 JSON](../c02-json)。
