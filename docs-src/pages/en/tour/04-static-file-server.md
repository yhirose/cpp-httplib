---
title: "Static File Server"
order: 4
draft: true
---

cpp-httplib can serve static files too — HTML, CSS, images, you name it. No complicated configuration required. One call to `set_mount_point()` is all it takes.

## The basics of set_mount_point

Let's jump right in. `set_mount_point()` maps a URL path to a local directory.

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server svr;

    svr.set_mount_point("/", "./html");

    std::cout << "Listening on port 8080..." << std::endl;
    svr.listen("0.0.0.0", 8080);
}
```

The first argument is the URL mount point. The second is the local directory path. In this example, requests to `/` are served from the `./html` directory.

Let's try it out. First, create an `html` directory and add an `index.html` file.

```sh
mkdir html
```

```html
<!DOCTYPE html>
<html>
<head><title>My Page</title></head>
<body>
    <h1>Hello from cpp-httplib!</h1>
    <p>This is a static file.</p>
</body>
</html>
```

Compile and start the server.

```sh
g++ -std=c++17 -o server server.cpp -pthread
./server
```

Open `http://localhost:8080` in your browser. You should see the contents of `html/index.html`. Visiting `http://localhost:8080/index.html` returns the same page.

You can also access it with the client code from the previous chapter, or with `curl`.

```cpp
httplib::Client cli("http://localhost:8080");
auto res = cli.Get("/");
if (res) {
    std::cout << res->body << std::endl;  // HTML is displayed
}
```

```sh
curl http://localhost:8080
```

## Multiple mount points

You can call `set_mount_point()` as many times as you like. Each URL path gets its own directory.

```cpp
svr.set_mount_point("/", "./public");
svr.set_mount_point("/assets", "./static/assets");
svr.set_mount_point("/docs", "./documentation");
```

A request to `/assets/style.css` serves `./static/assets/style.css`. A request to `/docs/guide.html` serves `./documentation/guide.html`.

## Combining with handlers

Static file serving and routing handlers — the kind you learned about in the previous chapter — work side by side.

```cpp
httplib::Server svr;

// API endpoint
svr.Get("/api/hello", [](const auto &, auto &res) {
    res.set_content(R"({"message":"Hello!"})", "application/json");
});

// Static file serving
svr.set_mount_point("/", "./public");

svr.listen("0.0.0.0", 8080);
```

Handlers take priority. The handler responds to `/api/hello`. For every other path, the server looks for a file in `./public`.

## Adding response headers

Pass headers as the third argument to `set_mount_point()` and they get attached to every static file response. This is great for cache control.

```cpp
svr.set_mount_point("/", "./public", {
    {"Cache-Control", "max-age=3600"}
});
```

With this in place, the browser caches served files for one hour.

## A Dockerfile for your static file server

The cpp-httplib repository includes a `Dockerfile` built for static file serving. We also publish a pre-built image on Docker Hub, so you can get up and running with a single command.

```sh
> docker run -p 8080:80 -v ./my-site:/html yhirose4dockerhub/cpp-httplib-server
Serving HTTP on 0.0.0.0:80
Mount point: / -> ./html
Press Ctrl+C to shutdown gracefully...
192.168.65.1 - - [22/Feb/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 256 "-" "Mozilla/5.0 ..."
192.168.65.1 - - [22/Feb/2026:12:00:00 +0000] "GET /style.css HTTP/1.1" 200 1024 "-" "Mozilla/5.0 ..."
192.168.65.1 - - [22/Feb/2026:12:00:01 +0000] "GET /favicon.ico HTTP/1.1" 404 152 "-" "Mozilla/5.0 ..."
```

Everything in your `./my-site` directory gets served on port 8080. The access log follows the same format as NGINX, so you can see exactly what's happening.

## What's next

You can now serve static files. A web server that delivers HTML, CSS, and JavaScript — built with this little code.

Next, let's encrypt your connections with HTTPS. We'll start by setting up a TLS library.

**Next:** [TLS Setup](../05-tls-setup)
