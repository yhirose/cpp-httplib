---
title: "S23. Handle custom HTTP methods"
order: 42
status: "draft"
---

The server rejects HTTP methods it does not know with `400 Bad Request`. To accept an extension method, such as the WebDAV methods of RFC 4918 (`PROPFIND`, `PROPPATCH`, `MKCOL` and friends) or UPnP's `SUBSCRIBE`, register a handler with `CustomRoute()`. Registering the handler is what makes the server accept the method.

## Basic usage

```cpp
svr.CustomRoute("PROPFIND", "/dav/:id",
                [](const httplib::Request &req, httplib::Response &res) {
                  // The request body is available as usual
                  auto id = req.path_params.at("id");
                  res.status = httplib::StatusCode::MultiStatus_207;
                  res.set_content(build_multistatus(req.body), "application/xml");
                });
```

Patterns work the same way as they do for `Get()`. Regular expressions and path parameters are both available.

## Advertise your methods with OPTIONS

A WebDAV client asks the server about its capabilities with `OPTIONS` before doing anything else. cpp-httplib generates neither the `DAV:` header nor `Allow`, so return them yourself. Forget this and clients will turn you away even though your `PROPFIND` works.

```cpp
svr.Options("/dav/.*", [](const httplib::Request &req, httplib::Response &res) {
  res.set_header("DAV", "1");
  res.set_header("Allow", "OPTIONS, GET, HEAD, PROPFIND, PROPPATCH, MKCOL");
});
```

## Read the body as a stream

There is a content reader overload, just like the one on `Post()`. Use it when you would rather not hold a large XML document in memory all at once.

```cpp
svr.CustomRoute("REPORT", "/dav/.*",
                [](const httplib::Request &req, httplib::Response &res,
                   const httplib::ContentReader &content_reader) {
                  content_reader([&](const char *data, size_t data_length) {
                    // Process it a chunk at a time
                    return true;
                  });
                  res.status = httplib::StatusCode::MultiStatus_207;
                });
```

## Things to keep in mind

- The method name has to be a valid HTTP method token (RFC 9110), and it must be registered before you call `listen()`
- `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `CONNECT`, `OPTIONS`, `TRACE`, `PATCH` and `PRI` cannot be registered here. Use the dedicated methods for those
- A rejected registration makes `is_valid()` return `false` and `listen()` fail, so the server never starts holding a handler that would never run
- Static file serving and WebSocket upgrades stay `GET`/`HEAD` only

> **Note:** cpp-httplib takes you as far as routing the method. If you want to call it WebDAV, generating the `207 Multi-Status` XML, interpreting the `Depth` header and managing locks are all yours to implement. The protocol itself lives outside the library.

> For the basics of registering handlers, see [S01. Register GET / POST / PUT / DELETE handlers](../s01-handlers).
