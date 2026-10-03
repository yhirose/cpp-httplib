---
title: "S12. 使用 res.user_data 在处理器之间传递数据"
order: 31
status: "draft"
---

假设你的 pre-request 处理器解码了一个认证令牌，而你想让路由处理器使用该结果。这种“处理器之间的数据传递”正是 `res.user_data` 的用途——它可以保存任意类型的值。

## 基本用法

```cpp
struct AuthUser {
  std::string id;
  std::string name;
  bool is_admin;
};

svr.set_pre_request_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    auto token = req.get_header_value("Authorization");
    auto user = decode_token(token); // 解码认证令牌
    res.user_data.set("user", user);
    return httplib::Server::HandlerResponse::Unhandled;
  });

svr.Get("/me", [](const httplib::Request &req, httplib::Response &res) {
  auto *user = res.user_data.get<AuthUser>("user");
  if (!user) {
    res.status = 401;
    return;
  }
  res.set_content("Hello, " + user->name, "text/plain");
});
```

`user_data.set()` 存储任意类型的值，`user_data.get<T>()` 取出它。如果你给出的类型不对，会得到 `nullptr`——所以要小心。

## 典型的值类型

字符串、数字、结构体、`std::shared_ptr`——任何可拷贝或可移动的类型都可以。

```cpp
res.user_data.set("user_id", std::string{"42"});
res.user_data.set("is_admin", true);
res.user_data.set("started_at", std::chrono::steady_clock::now());
```

## 在哪里设置，在哪里读取

通常的流程是：在 `set_pre_routing_handler()` 或 `set_pre_request_handler()` 中设置，在路由处理器中读取。pre-request 在路由之后运行，因此你可以结合 `req.matched_route`，只为特定路由设置值。

## 一个坑

`user_data` 存在于 `Response` 上，而不是 `Request` 上。这是因为处理器拿到的是 `Response&`（可修改），但只能拿到 `const Request&`。乍看之下有些奇怪，但一旦把它理解为“处理器之间共享的可变上下文”，就说得通了。

> **警告：** 当类型不匹配时，`user_data.get<T>()` 会返回 `nullptr`。在 set 和 get 时使用完全相同的类型。以 `AuthUser` 存储而以 `const AuthUser` 取出是行不通的。
