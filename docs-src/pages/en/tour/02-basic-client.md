---
title: "Basic Client"
order: 2
---

cpp-httplib isn't just for servers -- it also comes with a full HTTP client. Let's use `httplib::Client` to send GET and POST requests.

## Preparing a Test Server

To try out the client, you need a server that accepts requests. Save the following code, then compile and run it the same way you did in the previous chapter. We'll cover the server details in the next chapter.

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server svr;

    svr.Get("/hi", [](const auto &, auto &res) {
        res.set_content("Hello!", "text/plain");
    });

    svr.Get("/search", [](const auto &req, auto &res) {
        auto q = req.get_param_value("q");
        res.set_content("Query: " + q, "text/plain");
    });

    svr.Post("/post", [](const auto &req, auto &res) {
        res.set_content(req.body, "text/plain");
    });

    svr.Post("/submit", [](const auto &req, auto &res) {
        std::string result;
        for (auto &[key, val] : req.params) {
            result += key + " = " + val + "\n";
        }
        res.set_content(result, "text/plain");
    });

    svr.Post("/upload", [](const auto &req, auto &res) {
        auto f = req.form.get_file("file");
        auto content = f.filename + " (" + std::to_string(f.content.size()) + " bytes)";
        res.set_content(content, "text/plain");
    });

    svr.Get("/users/:id", [](const auto &req, auto &res) {
        auto id = req.path_params.at("id");
        res.set_content("User ID: " + id, "text/plain");
    });

    svr.Get(R"(/files/(\d+))", [](const auto &req, auto &res) {
        auto id = req.matches[1];
        res.set_content("File ID: " + std::string(id), "text/plain");
    });

    std::cout << "Listening on port 8080..." << std::endl;
    svr.listen("0.0.0.0", 8080);
}
```

## GET Request

Once the server is running, open a separate terminal and give it a try. Let's start with the simplest GET request.

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("http://localhost:8080");

    auto res = cli.Get("/hi");
    if (res) {
        std::cout << res->status << std::endl;  // 200
        std::cout << res->body << std::endl;    // Hello!
    }
}
```

Pass the server address to the `httplib::Client` constructor, then call `Get()` to send a request. You can retrieve the status code and body from the returned `res`.

Here's the equivalent `curl` command.

```sh
curl http://localhost:8080/hi
# Hello!
```

## Checking the Response

A response contains header information in addition to the status code and body.

```cpp
auto res = cli.Get("/hi");
if (res) {
    // Status code
    std::cout << res->status << std::endl;  // 200

    // Body
    std::cout << res->body << std::endl;  // Hello!

    // Headers
    std::cout << res->get_header_value("Content-Type") << std::endl;  // text/plain
}
```

`res->body` is a `std::string`, so if you want to parse a JSON response, you can pass it directly to a JSON library like [nlohmann/json](https://github.com/nlohmann/json).

## Query Parameters

To add query parameters to a GET request, you can either write them directly in the URL or use `httplib::Params`.

```cpp
auto res = cli.Get("/search", httplib::Params{{"q", "cpp-httplib"}});
if (res) {
    std::cout << res->body << std::endl;  // Query: cpp-httplib
}
```

`httplib::Params` automatically URL-encodes special characters for you.

```sh
curl "http://localhost:8080/search?q=cpp-httplib"
# Query: cpp-httplib
```

## Path Parameters

When values are embedded directly in the URL path, no special client API is needed. Just pass the path to `Get()` as-is.

```cpp
auto res = cli.Get("/users/42");
if (res) {
    std::cout << res->body << std::endl;  // User ID: 42
}
```

```sh
curl http://localhost:8080/users/42
# User ID: 42
```

The test server also has a `/files/(\d+)` route that uses a regex to accept numeric IDs only.

```cpp
auto res = cli.Get("/files/42");
if (res) {
    std::cout << res->body << std::endl;  // File ID: 42
}
```

```sh
curl http://localhost:8080/files/42
# File ID: 42
```

Pass a non-numeric ID like `/files/abc` and you'll get a 404. We'll cover how that works in the next chapter.

## Request Headers

To add custom HTTP headers, pass an `httplib::Headers` object. This works with both `Get()` and `Post()`.

```cpp
auto res = cli.Get("/hi", httplib::Headers{
    {"Authorization", "Bearer my-token"}
});
```

```sh
curl -H "Authorization: Bearer my-token" http://localhost:8080/hi
```

## POST Request

Let's POST some text data. Pass the body as the second argument to `Post()` and the Content-Type as the third.

```cpp
auto res = cli.Post("/post", "Hello, Server!", "text/plain");
if (res) {
    std::cout << res->status << std::endl;  // 200
    std::cout << res->body << std::endl;    // Hello, Server!
}
```

The test server's `/post` endpoint echoes the body back, so you get the same string you sent.

```sh
curl -X POST -H "Content-Type: text/plain" -d "Hello, Server!" http://localhost:8080/post
# Hello, Server!
```

## Sending Form Data

You can send key-value pairs just like an HTML form. Use `httplib::Params` for this.

```cpp
auto res = cli.Post("/submit", httplib::Params{
    {"name", "Alice"},
    {"age", "30"}
});
if (res) {
    std::cout << res->body << std::endl;
    // age = 30
    // name = Alice
}
```

This sends the data in `application/x-www-form-urlencoded` format.

```sh
curl -X POST -d "name=Alice&age=30" http://localhost:8080/submit
```

## POSTing a File

To upload a file, use `httplib::UploadFormDataItems` to send it as multipart form data.

```cpp
auto res = cli.Post("/upload", httplib::UploadFormDataItems{
    {"file", "Hello, File!", "hello.txt", "text/plain"}
});
if (res) {
    std::cout << res->body << std::endl;  // hello.txt (12 bytes)
}
```

Each element in `UploadFormDataItems` has four fields: `{name, content, filename, content_type}`.

```sh
curl -F "file=Hello, File!;filename=hello.txt;type=text/plain" http://localhost:8080/upload
```

## Error Handling

Network communication can fail -- the server might not be reachable. Always check whether `res` is valid.

```cpp
httplib::Client cli("http://localhost:9999");  // Non-existent port
auto res = cli.Get("/hi");

if (!res) {
    // Connection error
    std::cout << "Error: " << httplib::to_string(res.error()) << std::endl;
    // Error: Connection
    return 1;
}

// If we reach here, we have a response
if (res->status != 200) {
    std::cout << "HTTP Error: " << res->status << std::endl;
    return 1;
}

std::cout << res->body << std::endl;
```

There are two levels of errors.

- **Connection error**: The client couldn't reach the server. `res` evaluates to false, and you can call `res.error()` to find out what went wrong.
- **HTTP error**: The server returned an error status (404, 500, etc.). `res` evaluates to true, but you need to check `res->status`.

## Next Steps

Now you know how to send requests from a client. Next, let's take a closer look at the server side. We'll dig into routing, path parameters, and more.

**Next:** [Basic Server](../03-basic-server)
