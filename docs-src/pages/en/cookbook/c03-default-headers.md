---
title: "C03. Set Default Headers"
order: 3
status: "draft"
---

When you want the same headers on every request, use `set_default_headers()`. Once set, they're attached automatically to every request sent from that client.

## Basic usage

```cpp
httplib::Client cli("https://api.example.com");

cli.set_default_headers({
  {"Accept", "application/json"},
  {"User-Agent", "my-app/1.0"},
});

auto res = cli.Get("/users");
```

Register the headers you need on every API call — like `Accept` or `User-Agent` — in one place. No need to repeat them on each request.

## Send a Bearer token on every request

```cpp
httplib::Client cli("https://api.example.com");

cli.set_default_headers({
  {"Authorization", "Bearer " + token},
  {"Accept", "application/json"},
});

auto res1 = cli.Get("/me");
auto res2 = cli.Get("/projects");
```

Set the auth token once, and every subsequent request carries it. Handy when you're writing an API client that hits multiple endpoints.

> **Note:** `set_default_headers()` **replaces** the existing default headers. Even if you only want to add one, pass the full set again.

## Combine with per-request headers

You can still pass extra headers on individual requests, even with defaults set.

```cpp
httplib::Headers headers = {
  {"X-Request-ID", "abc-123"},
};
auto res = cli.Get("/users", headers);
```

Per-request headers are **added** on top of the defaults. Both are sent to the server.

> For details on Bearer token auth, see [C06. Call an API with a Bearer token](c06-bearer-token).
