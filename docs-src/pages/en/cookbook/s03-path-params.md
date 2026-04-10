---
title: "S03. Use Path Parameters"
order: 22
status: "draft"
---

For dynamic URLs like `/users/:id` — the staple of REST APIs — just put `:name` in the path pattern. The matched values end up in `req.path_params`.

## Basic usage

```cpp
svr.Get("/users/:id", [](const httplib::Request &req, httplib::Response &res) {
  auto id = req.path_params.at("id");
  res.set_content("user id: " + id, "text/plain");
});
```

A request to `/users/42` fills `req.path_params["id"]` with `"42"`. `path_params` is a `std::unordered_map<std::string, std::string>`, so use `at()` to read it.

## Multiple parameters

You can have as many as you need.

```cpp
svr.Get("/orgs/:org/repos/:repo", [](const httplib::Request &req, httplib::Response &res) {
  auto org = req.path_params.at("org");
  auto repo = req.path_params.at("repo");
  res.set_content(org + "/" + repo, "text/plain");
});
```

This matches paths like `/orgs/anthropic/repos/cpp-httplib`.

## Regex patterns

For more flexible matching, use a `std::regex`-based pattern.

```cpp
svr.Get(R"(/users/(\d+))", [](const httplib::Request &req, httplib::Response &res) {
  auto id = req.matches[1];
  res.set_content("user id: " + std::string(id), "text/plain");
});
```

Parentheses in the pattern become captures in `req.matches`. `req.matches[0]` is the full match; `req.matches[1]` onward are the captures.

## Which to use

- For plain IDs or slugs, `:name` is enough — readable, and the shape is obvious
- Use regex when you want to constrain the URL to, say, numbers only or a UUID format
- Mixing both can get confusing — stick with one style per project

> **Note:** Path parameters come in as strings. If you need an integer, convert with `std::stoi()` and don't forget to handle conversion errors.
