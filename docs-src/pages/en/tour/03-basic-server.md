---
title: "Basic Server"
order: 3
---

In the previous chapter, you sent requests from a client using `test_server.cpp`. Now let's walk through how that server actually works.

## Starting the Server

Once you've registered your routes, call `svr.listen()` to start the server.

```cpp
svr.listen("0.0.0.0", 8080);
```

The first argument is the host, and the second is the port. `"0.0.0.0"` listens on all network interfaces. Use `"127.0.0.1"` if you want to accept connections from your own machine only.

`listen()` is a blocking call. It won't return until the server stops. The server keeps running until you press `Ctrl+C` in your terminal or call `svr.stop()` from another thread.

## Routing

Routing is the heart of any server. It's how you tell cpp-httplib: when a request comes in for this URL with this HTTP method, run this code.

```cpp
httplib::Server svr;

svr.Get("/hi", [](const httplib::Request &req, httplib::Response &res) {
    res.set_content("Hello!", "text/plain");
});
```

`svr.Get()` registers a handler for GET requests. The first argument is the path, the second is the handler function. When a GET request arrives at `/hi`, your lambda runs.

There's a method for each HTTP verb.

```cpp
svr.Get("/path",    handler);  // GET
svr.Post("/path",   handler);  // POST
svr.Put("/path",    handler);  // PUT
svr.Delete("/path", handler);  // DELETE
```

The handler signature is `(const httplib::Request &req, httplib::Response &res)`. You can use `auto` to keep it short.

```cpp
svr.Get("/hi", [](const auto &req, auto &res) {
    res.set_content("Hello!", "text/plain");
});
```

The handler only runs when the path matches. Requests to unregistered paths automatically return 404.

## The Request Object

The first parameter `req` gives you everything the client sent.

### Body

`req.body` holds the request body as a `std::string`.

```cpp
svr.Post("/post", [](const auto &req, auto &res) {
    // Echo the body back to the client
    res.set_content(req.body, "text/plain");
});
```

### Headers

Use `req.get_header_value()` to read a request header.

```cpp
svr.Get("/check", [](const auto &req, auto &res) {
    auto auth = req.get_header_value("Authorization");
    res.set_content("Auth: " + auth, "text/plain");
});
```

### Query Parameters and Form Data

`req.get_param_value()` retrieves a parameter by name. It works for both GET query parameters and POST form data.

```cpp
svr.Get("/search", [](const auto &req, auto &res) {
    auto q = req.get_param_value("q");
    res.set_content("Query: " + q, "text/plain");
});
```

A request to `/search?q=cpp-httplib` gives you `"cpp-httplib"` for `q`.

To loop over all parameters, use `req.params`.

```cpp
svr.Post("/submit", [](const auto &req, auto &res) {
    std::string result;
    for (auto &[key, val] : req.params) {
        result += key + " = " + val + "\n";
    }
    res.set_content(result, "text/plain");
});
```

### File Uploads

Files uploaded via multipart form data are available through `req.form.get_file()`.

```cpp
svr.Post("/upload", [](const auto &req, auto &res) {
    auto f = req.form.get_file("file");
    auto content = f.filename + " (" + std::to_string(f.content.size()) + " bytes)";
    res.set_content(content, "text/plain");
});
```

`f.filename` gives you the filename, and `f.content` gives you the file data.

## Path Parameters

Sometimes you want to capture part of the URL as a variable -- for example, the `42` in `/users/42`. Use the `:param` syntax to do that.

```cpp
svr.Get("/users/:id", [](const auto &req, auto &res) {
    auto id = req.path_params.at("id");
    res.set_content("User ID: " + id, "text/plain");
});
```

A request to `/users/42` gives you `"42"` from `req.path_params.at("id")`. `/users/100` gives you `"100"`.

You can capture multiple segments at once.

```cpp
svr.Get("/users/:user_id/posts/:post_id", [](const auto &req, auto &res) {
    auto user_id = req.path_params.at("user_id");
    auto post_id = req.path_params.at("post_id");
    res.set_content("User: " + user_id + ", Post: " + post_id, "text/plain");
});
```

### Regex Patterns

You can also write a regular expression directly in the path instead of `:param`. Capture group values are available via `req.matches`, which is a `std::smatch`.

```cpp
// Only accept numeric IDs
svr.Get(R"(/files/(\d+))", [](const auto &req, auto &res) {
    auto id = req.matches[1];  // First capture group
    res.set_content("File ID: " + std::string(id), "text/plain");
});
```

`/files/42` matches, but `/files/abc` doesn't. This is handy when you want to constrain what values are accepted.

## Building a Response

The second parameter `res` is how you send data back to the client.

### Body and Content-Type

`res.set_content()` sets the body and Content-Type. That's all you need for a 200 response.

```cpp
svr.Get("/hi", [](const auto &req, auto &res) {
    res.set_content("Hello!", "text/plain");
});
```

### Status Code

To return a different status code, assign to `res.status`.

```cpp
svr.Get("/not-found", [](const auto &req, auto &res) {
    res.status = 404;
    res.set_content("Not found", "text/plain");
});
```

### Response Headers

Add response headers with `res.set_header()`.

```cpp
svr.Get("/with-header", [](const auto &req, auto &res) {
    res.set_header("X-Custom", "my-value");
    res.set_content("Hello!", "text/plain");
});
```

## Walking Through the Test Server

Now let's use what we've learned to read through the `test_server.cpp` from the previous chapter.

### GET /hi

```cpp
svr.Get("/hi", [](const auto &, auto &res) {
    res.set_content("Hello!", "text/plain");
});
```

The simplest possible handler. We don't need any information from the request, so the `req` parameter is left unnamed. It just returns `"Hello!"`.

### GET /search

```cpp
svr.Get("/search", [](const auto &req, auto &res) {
    auto q = req.get_param_value("q");
    res.set_content("Query: " + q, "text/plain");
});
```

`req.get_param_value("q")` pulls out the query parameter `q`. A request to `/search?q=cpp-httplib` returns `"Query: cpp-httplib"`.

### POST /post

```cpp
svr.Post("/post", [](const auto &req, auto &res) {
    res.set_content(req.body, "text/plain");
});
```

An echo server. Whatever body the client sends, `req.body` holds it, and we send it straight back.

### POST /submit

```cpp
svr.Post("/submit", [](const auto &req, auto &res) {
    std::string result;
    for (auto &[key, val] : req.params) {
        result += key + " = " + val + "\n";
    }
    res.set_content(result, "text/plain");
});
```

Loops over the form data in `req.params` using structured bindings (`auto &[key, val]`) to unpack each key-value pair.

### POST /upload

```cpp
svr.Post("/upload", [](const auto &req, auto &res) {
    auto f = req.form.get_file("file");
    auto content = f.filename + " (" + std::to_string(f.content.size()) + " bytes)";
    res.set_content(content, "text/plain");
});
```

Receives a file uploaded via multipart form data. `req.form.get_file("file")` fetches the field named `"file"`, and we respond with the filename and size.

### GET /users/:id

```cpp
svr.Get("/users/:id", [](const auto &req, auto &res) {
    auto id = req.path_params.at("id");
    res.set_content("User ID: " + id, "text/plain");
});
```

`:id` is the path parameter. `req.path_params.at("id")` retrieves its value. `/users/42` gives you `"42"`, `/users/alice` gives you `"alice"`.

### GET /files/(\d+)

```cpp
svr.Get(R"(/files/(\d+))", [](const auto &req, auto &res) {
    auto id = req.matches[1];
    res.set_content("File ID: " + std::string(id), "text/plain");
});
```

The regex `(\d+)` matches numeric IDs only. `/files/42` hits this handler, but `/files/abc` returns 404. `req.matches[1]` retrieves the first capture group.

## Next Steps

You now have the full picture of how a server works. Routing, reading requests, building responses -- that's enough to build a real API server.

Next, let's look at serving static files. We'll build a server that delivers HTML and CSS.

**Next:** [Static File Server](../04-static-file-server)
