---
title: "S11. 使用 pre-request 处理器按路由认证"
order: 30
status: "draft"
---

来自 [S09. 为所有路由添加预处理](../s09-pre-routing) 的 `set_pre_routing_handler()` 在**路由之前**运行，因此它并不知道匹配了哪条路由。当你需要按路由的行为时，`set_pre_request_handler()` 正是你需要的。

## Pre-routing 与 pre-request 的对比

| 钩子 | 运行时机 | 路由信息 | 请求体 |
| --- | --- | --- | --- |
| `set_pre_routing_handler` | 路由之前 | 不可用 | 尚未读取 |
| `set_pre_request_handler` | 路由之后、紧接路由处理器之前 | 可通过 `req.matched_route` 获取 | 尚未读取 |

在 pre-request 处理器中，`req.matched_route` 保存匹配到的**模式字符串**。你可以根据路由定义本身来改变行为。

由于 pre-request 处理器运行时请求体尚未被读取，你可以拒绝一个请求——例如认证检查失败时——而无需消费（可能很大的）请求体。请注意，这也意味着此处的 `req.body` 以及从请求体解析出的表单字段都不可用；请改为检查请求头、路径、查询参数或 `req.matched_route`。

## 按路由切换认证

```cpp
svr.set_pre_request_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    // 对以 /admin 开头的路由要求认证
    if (req.matched_route.rfind("/admin", 0) == 0) {
      auto token = req.get_header_value("Authorization");
      if (!is_admin_token(token)) {
        res.status = 403;
        res.set_content("forbidden", "text/plain");
        return httplib::Server::HandlerResponse::Handled;
      }
    }
    return httplib::Server::HandlerResponse::Unhandled;
  });
```

`matched_route` 是路径参数展开**之前**的模式（例如 `/admin/users/:id`）。你比较的是路由定义，而不是实际请求路径，因此 ID 或名称不会干扰你。

pre-request 处理器对使用 `svr.WebSocket()` 注册的路由也会运行。它在 `101 Switching Protocols` 响应之前被调用，因此返回 `Handled` 会发送你的 HTTP 响应（例如 403），连接永远不会升级。

## 返回值

与 pre-routing 相同——返回 `HandlerResponse`。

- `Unhandled`：继续（路由处理器会运行）
- `Handled`：已完成，跳过路由处理器

## 将认证信息传递给路由处理器

要将解码后的用户信息传入路由处理器，请使用 `res.user_data`。请参阅 [S12. 使用 `res.user_data` 在处理器之间传递数据](../s12-user-data)。
