---
title: "S03. 使用路径参数"
order: 22
status: "draft"
---

对于像 `/users/:id` 这样的动态 URL——REST API 的常见形式——只需在路径模式中放入 `:name`。匹配到的值会存放在 `req.path_params` 中。

## 基本用法

```cpp
svr.Get("/users/:id", [](const httplib::Request &req, httplib::Response &res) {
  auto id = req.path_params.at("id");
  res.set_content("user id: " + id, "text/plain");
});
```

对 `/users/42` 的请求会将 `req.path_params["id"]` 填充为 `"42"`。`path_params` 是一个 `std::unordered_map<std::string, std::string>`，因此请使用 `at()` 读取它。

## 多个参数

你可以按需定义任意多个参数。

```cpp
svr.Get("/orgs/:org/repos/:repo", [](const httplib::Request &req, httplib::Response &res) {
  auto org = req.path_params.at("org");
  auto repo = req.path_params.at("repo");
  res.set_content(org + "/" + repo, "text/plain");
});
```

这会匹配类似 `/orgs/anthropic/repos/cpp-httplib` 的路径。

## 正则表达式模式

若需要更灵活的匹配，请使用基于 `std::regex` 的模式。

```cpp
svr.Get(R"(/users/(\d+))", [](const httplib::Request &req, httplib::Response &res) {
  auto id = req.matches[1];
  res.set_content("user id: " + std::string(id), "text/plain");
});
```

模式中的圆括号会成为 `req.matches` 中的捕获组。`req.matches[0]` 是完整匹配；从 `req.matches[1]` 开始是各个捕获组。

## 该用哪一种

- 对于普通的 ID 或 slug，`:name` 就足够了——可读性好，而且形式一目了然
- 当你需要将 URL 约束为（例如）纯数字或 UUID 格式时，请使用正则表达式
- 混用两者可能会令人困惑——每个项目坚持使用一种风格

> **注意：** 路径参数以字符串形式传入。如果你需要整数，请使用 `std::stoi()` 进行转换，并且不要忘记处理转换错误。
