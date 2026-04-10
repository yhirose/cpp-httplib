---
title: "C02. Send and Receive JSON"
order: 2
status: "draft"
---

cpp-httplib doesn't include a JSON parser. Use a library like [nlohmann/json](https://github.com/nlohmann/json) to build and parse JSON. The examples here use `nlohmann/json`.

## Send JSON

```cpp
httplib::Client cli("http://localhost:8080");

nlohmann::json j = {{"name", "Alice"}, {"age", 30}};
auto res = cli.Post("/api/users", j.dump(), "application/json");
```

Pass the JSON string as the second argument to `Post()` and the Content-Type as the third. The same pattern works with `Put()` and `Patch()`.

> **Warning:** If you omit the Content-Type (the third argument), the server may not recognize the body as JSON. Always specify `"application/json"`.

## Receive a JSON response

```cpp
auto res = cli.Get("/api/users/1");
if (res && res->status == 200) {
  auto j = nlohmann::json::parse(res->body);
  std::cout << j["name"] << std::endl;
}
```

`res->body` is a `std::string`, so you can pass it straight to your JSON library.

> **Note:** Servers sometimes return HTML on errors. Check the status code before parsing to be safe. Some APIs also require an `Accept: application/json` header. If you're calling a JSON API repeatedly, C03. Set default headers can save you some boilerplate.

> For how to receive and return JSON on the server side, see S02. Receive JSON requests and return JSON responses.
