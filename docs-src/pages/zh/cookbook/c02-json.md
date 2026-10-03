---
title: "C02. 发送和接收 JSON"
order: 2
status: "draft"
---

cpp-httplib 不包含 JSON 解析器。可以使用 [nlohmann/json](https://github.com/nlohmann/json) 之类的库来构建和解析 JSON。这里的示例使用 `nlohmann/json`。

## 发送 JSON

```cpp
httplib::Client cli("http://localhost:8080");

nlohmann::json j = {{"name", "Alice"}, {"age", 30}};
auto res = cli.Post("/api/users", j.dump(), "application/json");
```

把 JSON 字符串作为第二个参数传给 `Post()`，把 Content-Type 作为第三个参数。同样的模式也适用于 `Put()` 和 `Patch()`。

> **警告：** 如果省略 Content-Type（第三个参数），服务器可能无法将请求体识别为 JSON。请始终指定 `"application/json"`。

## 接收 JSON 响应

```cpp
auto res = cli.Get("/api/users/1");
if (res && res->status == 200) {
  auto j = nlohmann::json::parse(res->body);
  std::cout << j["name"] << std::endl;
}
```

`res->body` 是一个 `std::string`，因此可以直接传给你的 JSON 库。

> **注意：** 服务器有时会在出错时返回 HTML。为保险起见，请在解析前检查状态码。有些 API 还要求带上 `Accept: application/json` 请求头。如果你要反复调用某个 JSON API，[C03. 设置默认请求头](../c03-default-headers) 可以帮你省去一些样板代码。

> 关于如何在服务器端接收和返回 JSON，请参见 [S02. 接收 JSON 请求并返回 JSON 响应](../s02-json-api)。
