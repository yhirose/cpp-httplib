---
title: "S02. Receive a JSON Request and Return a JSON Response"
order: 21
status: "draft"
---

cpp-httplib doesn't include a JSON parser. On the server side, combine it with something like [nlohmann/json](https://github.com/nlohmann/json). The examples below use `nlohmann/json`.

## Receive and return JSON

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

`req.body` is a plain `std::string`, so you pass it straight to your JSON library. For the response, `dump()` to a string and set the Content-Type to `application/json`.

## Check the Content-Type

```cpp
svr.Post("/api/users", [](const httplib::Request &req, httplib::Response &res) {
  auto content_type = req.get_header_value("Content-Type");
  if (content_type.find("application/json") == std::string::npos) {
    res.status = 415; // Unsupported Media Type
    return;
  }
  // ...
});
```

When you strictly want JSON only, verify the Content-Type up front.

## A helper for JSON responses

If you're writing the same pattern repeatedly, a small helper saves typing.

```cpp
auto send_json = [](httplib::Response &res, int status, const nlohmann::json &j) {
  res.status = status;
  res.set_content(j.dump(), "application/json");
};

svr.Get("/api/health", [&](const auto &req, auto &res) {
  send_json(res, 200, {{"status", "ok"}});
});
```

> **Note:** A large JSON body ends up entirely in `req.body`, which means it all sits in memory. For huge payloads, consider streaming reception — see [S07. Receive multipart data as a stream](s07-multipart-reader).

> For the client side, see [C02. Send and receive JSON](c02-json).
