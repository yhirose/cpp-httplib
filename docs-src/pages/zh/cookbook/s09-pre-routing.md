---
title: "S09. 为所有路由添加预处理"
order: 28
status: "draft"
---

有时你希望在每个请求之前运行相同的逻辑——认证检查、日志记录、限流。请使用 `set_pre_routing_handler()` 注册这些逻辑。

## 基本用法

```cpp
svr.set_pre_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    std::cout << req.method << " " << req.path << std::endl;
    return httplib::Server::HandlerResponse::Unhandled;
  });
```

pre-routing 处理器在**路由之前**运行。它会捕获每一个请求——包括不匹配任何处理器的请求。

`HandlerResponse` 返回值是关键：

- 返回 `Unhandled` → 正常继续（路由和实际处理器都会运行）
- 返回 `Handled` → 响应被视为已完成，跳过其余部分

## 用它来做认证

把你共享的认证检查集中放在一个地方。

```cpp
svr.set_pre_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    if (req.path.rfind("/public", 0) == 0) {
      return httplib::Server::HandlerResponse::Unhandled; // 无需认证
    }

    auto auth = req.get_header_value("Authorization");
    if (auth.empty()) {
      res.status = 401;
      res.set_content("unauthorized", "text/plain");
      return httplib::Server::HandlerResponse::Handled;
    }

    return httplib::Server::HandlerResponse::Unhandled;
  });
```

如果认证失败，返回 `Handled` 立即以 401 响应。如果通过，返回 `Unhandled`，让路由接管。

## 用于按路由认证

如果你希望每条路由有不同的认证规则，而不是单一的全局检查，`set_pre_request_handler()` 更合适。请参阅 [S11. 使用 pre-request 处理器按路由认证](../s11-pre-request)。

> **注意：** 如果你只想修改响应，`set_post_routing_handler()` 才是合适的工具。请参阅 [S10. 使用 post-routing 处理器添加响应头](../s10-post-routing)。
