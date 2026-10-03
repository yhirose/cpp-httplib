---
title: "S14. 捕获异常"
order: 33
status: "draft"
---

当路由处理器抛出异常时，cpp-httplib 会保持服务器运行并返回 500 响应。但默认情况下，几乎没有错误信息能传到客户端。`set_exception_handler()` 让你可以拦截异常并构建自己的响应。

## 基本用法

```cpp
svr.set_exception_handler(
  [](const httplib::Request &req, httplib::Response &res,
     std::exception_ptr ep) {
    try {
      std::rethrow_exception(ep);
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content(std::string("error: ") + e.what(), "text/plain");
    } catch (...) {
      res.status = 500;
      res.set_content("unknown error", "text/plain");
    }
  });
```

处理器会收到一个 `std::exception_ptr`。惯用做法是用 `std::rethrow_exception()` 重新抛出它，并按类型捕获。你可以根据异常类型改变状态码和消息。

## 按自定义异常类型分支

如果你抛出自定义异常类型，可以将它们映射到 400 或 404 响应。

```cpp
struct NotFound : std::runtime_error {
  using std::runtime_error::runtime_error;
};
struct BadRequest : std::runtime_error {
  using std::runtime_error::runtime_error;
};

svr.set_exception_handler(
  [](const auto &req, auto &res, std::exception_ptr ep) {
    try {
      std::rethrow_exception(ep);
    } catch (const NotFound &e) {
      res.status = 404;
      res.set_content(e.what(), "text/plain");
    } catch (const BadRequest &e) {
      res.status = 400;
      res.set_content(e.what(), "text/plain");
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content("internal error", "text/plain");
    }
  });
```

现在，在处理器内抛出 `NotFound("user not found")` 就足以返回 404。无需为每个处理器写 try/catch。

## 与 set_error_handler 的关系

`set_exception_handler()` 在异常抛出的那一刻运行。之后，如果 `res.status` 是 4xx 或 5xx，`set_error_handler()` 也会运行。顺序是 `exception_handler` → `error_handler`。它们的职责可以这样理解：

- **异常处理器**：解释异常，设置状态码和消息
- **错误处理器**：读取状态码，并将其包装进共享模板

> **注意：** 如果没有异常处理器，cpp-httplib 会返回默认的 500 响应，异常详情永远不会进入日志。对于任何你想调试的内容，都应该设置一个。
