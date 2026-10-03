---
title: "S13. 返回自定义错误页面"
order: 32
status: "draft"
---

要自定义 4xx 或 5xx 错误的响应，请使用 `set_error_handler()`。你可以用自定义的 HTML 或 JSON 替换默认的简陋错误页面。

## 基本用法

```cpp
svr.set_error_handler([](const httplib::Request &req, httplib::Response &res) {
  auto body = "<h1>Error " + std::to_string(res.status) + "</h1>";
  res.set_content(body, "text/html");
});
```

错误处理器会在错误响应发送之前立即运行——只要 `res.status` 是 4xx 或 5xx 就会触发。用 `res.set_content()` 替换请求体后，每个错误响应都会使用相同的模板。

## 按状态码分支

```cpp
svr.set_error_handler([](const httplib::Request &req, httplib::Response &res) {
  if (res.status == 404) {
    res.set_content("<h1>Not Found</h1><p>" + req.path + "</p>", "text/html");
  } else if (res.status >= 500) {
    res.set_content("<h1>Server Error</h1>", "text/html");
  }
});
```

通过检查 `res.status`，你可以为 404 显示自定义消息，为 5xx 错误显示"联系支持"链接。

## JSON 错误响应

对于 API 服务器，你可能希望以 JSON 形式返回错误。

```cpp
svr.set_error_handler([](const httplib::Request &req, httplib::Response &res) {
  nlohmann::json j = {
    {"error", true},
    {"status", res.status},
    {"path", req.path},
  };
  res.set_content(j.dump(), "application/json");
});
```

现在每个错误都会以一致的 JSON 结构返回。

> **注意：** 当路由处理器抛出异常导致 500 响应时，`set_error_handler()` 也会触发。要获取异常本身，请将其与 `set_exception_handler()` 结合使用。参见 [S14. 捕获异常](../s14-exception-handler)。
