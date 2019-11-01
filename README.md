cpp-httplib
===========

[![](https://github.com/yhirose/cpp-httplib/workflows/test/badge.svg)](https://github.com/yhirose/cpp-httplib/actions)
[![Build Status](https://travis-ci.org/yhirose/cpp-httplib.svg?branch=master)](https://travis-ci.org/yhirose/cpp-httplib)
[![Bulid Status](https://ci.appveyor.com/api/projects/status/github/yhirose/cpp-httplib?branch=master&svg=true)](https://ci.appveyor.com/project/yhirose/cpp-httplib)

A C++ single-file header-only cross platform HTTP/HTTPS library.

It's extremely easy to setup. Just include **httplib.h** file in your code!

Server Example
--------------

```c++
#include <httplib.h>

int main(void)
{
    using namespace httplib;

    Server svr;

    svr.Get("/hi", [](const Request& req, Response& res) {
        res.set_content("Hello World!", "text/plain");
    });

    svr.Get(R"(/numbers/(\d+))", [&](const Request& req, Response& res) {
        auto numbers = req.matches[1];
        res.set_content(numbers, "text/plain");
    });

    svr.Get("/stop", [&](const Request& req, Response& res) {
        svr.stop();
    });

    svr.listen("localhost", 1234);
}
```

`Post`, `Put`, `Delete` and `Options` methods are also supported.

### Bind a socket to multiple interfaces and any available port

```cpp
int port = svr.bind_to_any_port("0.0.0.0");
svr.listen_after_bind();
```

### Static File Server

```cpp
svr.set_base_dir("./www");
```

### Logging

```cpp
svr.set_logger([](const auto& req, const auto& res) {
    your_logger(req, res);
});
```

### Error Handler

```cpp
svr.set_error_handler([](const auto& req, auto& res) {
    const char* fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
    char buf[BUFSIZ];
    snprintf(buf, sizeof(buf), fmt, res.status);
    res.set_content(buf, "text/html");
});
```

### 'multipart/form-data' POST data

```cpp
svr.Post("/multipart", [&](const auto& req, auto& res) {
    auto size = req.files.size();
    auto ret = req.has_file("name1");
    const auto& file = req.get_file_value("name1");
    // file.filename;
    // file.content_type;
    auto body = req.body.substr(file.offset, file.length);
});

```

### Stream content with Content provider

```cpp
const uint64_t DATA_CHUNK_SIZE = 4;

svr.Get("/stream", [&](const Request &req, Response &res) {
  auto data = new std::string("abcdefg");

  res.set_content_provider(
    data->size(), // Content length
    [data](uint64_t offset, uint64_t length, DataSink sink) {
      const auto &d = *data;
      sink(&d[offset], std::min(length, DATA_CHUNK_SIZE));
    },
    [data] { delete data; });
});
```

### Chunked transfer encoding

```cpp
svr.Get("/chunked", [&](const Request& req, Response& res) {
  res.set_chunked_content_provider(
    [](uint64_t offset, DataSink sink, Done done) {
       sink("123", 3);
       sink("345", 3);
       sink("789", 3);
       done();
    }
  );
});
```

### Default thread pool supporet

Set thread count to 8:

```cpp
#define CPPHTTPLIB_THREAD_POOL_COUNT 8
```

Disable the default thread pool:

```cpp
#define CPPHTTPLIB_THREAD_POOL_COUNT 0
```

### Override the default thread pool with yours

```cpp
class YourThreadPoolTaskQueue : public TaskQueue {
public:
  YourThreadPoolTaskQueue(size_t n) {
    pool_.start_with_thread_count(n);
  }

  virtual void enqueue(std::function<void()> fn) override {
    pool_.enqueue(fn);
  }

  virtual void shutdown() override {
    pool_.shutdown_gracefully();
  }

private:
  YourThreadPool pool_;
};

svr.new_task_queue = [] {
  return new YourThreadPoolTaskQueue(12);
};
```

Client Example
--------------

### GET

```c++
#include <httplib.h>
#include <iostream>

int main(void)
{
    httplib::Client cli("localhost", 1234);

    auto res = cli.Get("/hi");
    if (res && res->status == 200) {
        std::cout << res->body << std::endl;
    }
}
```

### GET with HTTP headers

```c++
  httplib::Headers headers = {
    { "Accept-Encoding", "gzip, deflate" }
  };
  auto res = cli.Get("/hi", headers);
```

### GET with Content Receiver

```c++
  std::string body;

  auto res = cli.Get("/large-data",
    [&](const char *data, uint64_t data_length) {
      body.append(data, data_length);
      return true;
    });

  assert(res->body.empty());
```

### POST

```c++
res = cli.Post("/post", "text", "text/plain");
res = cli.Post("/person", "name=john1&note=coder", "application/x-www-form-urlencoded");
```

### POST with parameters

```c++
httplib::Params params;
params.emplace("name", "john");
params.emplace("note", "coder");

auto res = cli.Post("/post", params);
```
 or

```c++
httplib::Params params{
  { "name", "john" },
  { "note", "coder" }
};

auto res = cli.Post("/post", params);
```

### POST with Multipart Form Data

```c++
  httplib::MultipartFormDataItems items = {
    { "text1", "text default", "", "" },
    { "text2", "aωb", "", "" },
    { "file1", "h\ne\n\nl\nl\no\n", "hello.txt", "text/plain" },
    { "file2", "{\n  \"world\", true\n}\n", "world.json", "application/json" },
    { "file3", "", "", "application/octet-stream" },
  };

  auto res = cli.Post("/multipart", items);
```

### PUT

```c++
res = cli.Put("/resource/foo", "text", "text/plain");
```

### DELETE

```c++
res = cli.Delete("/resource/foo");
```

### OPTIONS

```c++
res = cli.Options("*");
res = cli.Options("/resource/foo");
```

### Connection Timeout

```c++
httplib::Client cli("localhost", 8080, 5); // timeouts in 5 seconds
```
### With Progress Callback

```cpp
httplib::Client client(url, port);

// prints: 0 / 000 bytes => 50% complete
std::shared_ptr<httplib::Response> res =
    cli.Get("/", [](uint64_t len, uint64_t total) {
        printf("%lld / %lld bytes => %d%% complete\n",
            len, total,
            (int)((len/total)*100));
        return true; // return 'false' if you want to cancel the request.
    }
);
```

![progress](https://user-images.githubusercontent.com/236374/33138910-495c4ecc-cf86-11e7-8693-2fc6d09615c4.gif)

This feature was contributed by [underscorediscovery](https://github.com/yhirose/cpp-httplib/pull/23).

### Basic Authentication

```cpp
httplib::Client cli("httplib.org");

auto res = cli.Get("/basic-auth/hello/world", {
  httplib::make_basic_authentication_header("hello", "world")
});
// res->status should be 200
// res->body should be "{\n  \"authenticated\": true, \n  \"user\": \"hello\"\n}\n".
```

### Range

```cpp
httplib::Client cli("httpbin.org");

auto res = cli.Get("/range/32", {
  httplib::make_range_header({{1, 10}}) // 'Range: bytes=1-10'
});
// res->status should be 206.
// res->body should be "bcdefghijk".
```

```cpp
httplib::make_range_header({{1, 10}, {20, -1}})      // 'Range: bytes=1-10, 20-'
httplib::make_range_header({{100, 199}, {500, 599}}) // 'Range: bytes=100-199, 500-599'
httplib::make_range_header({{0, 0}, {-1, 1}})        // 'Range: bytes=0-0, -1'
```

### Keep-Alive connection

```cpp
cli.set_keep_alive_max_count(2); // Default is 5

std::vector<Request> requests;
Get(requests, "/get-request1");
Get(requests, "/get-request2");
Post(requests, "/post-request1", "text", "text/plain");
Post(requests, "/post-request2", "text", "text/plain");

std::vector<Response> responses;
if (cli.send(requests, responses)) {
  for (const auto& res: responses) {
    ...
  }
}
```

### Redirect

```cpp
httplib::Client cli("yahoo.com");

auto res = cli.Get("/");
res->status; // 301

cli.follow_location(true);
res = cli.Get("/");
res->status; // 200
```

OpenSSL Support
---------------

SSL support is available with `CPPHTTPLIB_OPENSSL_SUPPORT`. `libssl` and `libcrypto` should be linked.

```c++
#define CPPHTTPLIB_OPENSSL_SUPPORT

SSLServer svr("./cert.pem", "./key.pem");

SSLClient cli("localhost", 8080);
cli.set_ca_cert_path("./ca-bundle.crt");
cli.enable_server_certificate_verification(true);
```

Zlib Support
------------

'gzip' compression is available with `CPPHTTPLIB_ZLIB_SUPPORT`.

The server applies gzip compression to the following MIME type contents:

  * all text types
  * image/svg+xml
  * application/javascript
  * application/json
  * application/xml
  * application/xhtml+xml

NOTE
----

g++ 4.8 cannot build this library since `<regex>` in g++4.8 is [broken](https://stackoverflow.com/questions/12530406/is-gcc-4-8-or-earlier-buggy-about-regular-expressions).

License
-------

MIT license (© 2019 Yuji Hirose)
